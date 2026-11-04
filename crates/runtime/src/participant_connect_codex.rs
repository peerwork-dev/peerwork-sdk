//! Local-owner existing-Codex attachment. Low-level subscription selections and
//! stopped-runtime maintenance are internal to one durable job.
use super::*;
use crate::{
    communication_runtime::RuntimeConfig, participant_dispatch::HostSubscription,
    participant_rebind::HostRebindRequest,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attachment {
    setup_id: String,
    selected_chat: String,
    desired: ConnectRequest,
    invocation: ConnectRequest,
    #[serde(default,skip_serializing_if="Option::is_none")]
    owned: Option<bootstrap::OwnedRuntime>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    resident_admin: Option<PathBuf>,
    source_binding: Value,
    request: HostRebindRequest,
    committed: Option<RuntimeConfig>,
    #[serde(default)]
    finished: bool,
    #[serde(default)]
    aborted: bool,
}
fn failure(code: &str) -> ParticipantError {
    local(code)
}

fn select_session(sessions: &Value, choice: &str) -> Result<Value> {
    let matches: Vec<_> = sessions["sessions"]
        .as_array()
        .ok_or_else(|| local("HOST_RESPONSE_INVALID"))?
        .iter()
        .filter(|s| s["thread_id"] == choice || s["title"] == choice)
        .collect();
    if matches.len() != 1 {
        return Err(local(if matches.is_empty() {
            "CODEX_CHAT_NOT_LOADED"
        } else {
            "CODEX_CHAT_TITLE_AMBIGUOUS"
        }));
    }
    let selected = matches[0];
    Ok(
        json!({"kind":"codex","endpoint":"codex-proxy://local","thread_id":selected["thread_id"],"expected_session_id":selected["session_id"]}),
    )
}

fn desired_setup(
    source: &ConnectRequest,
    requested: &ConnectRequest,
    host: &str,
    seed: &str,
) -> Result<ConnectRequest> {
    let mut desired = source.clone();
    desired.setup_id = format!("codex-{}", &sha256_hex(seed.as_bytes())[..32]);
    desired.send |= requested.send;
    desired.require_body_keys |= requested.require_body_keys;
    desired.request_membership |= requested.request_membership;
    for operation in &requested.management {if !desired.management.contains(operation){desired.management.push(operation.clone());}}
    desired.management.sort();
    desired.receive = true;
    desired.receive_mode = Some(ReceiveMode::Push);
    desired.host = Some(host.into());
    for role in &requested.protocols {
        desired.protocols.retain(|old| old.alias != role.alias);
        desired.protocols.push(role.clone());
    }
    for contact in &requested.contacts {
        desired.contacts.retain(|old| old.alias != contact.alias);
        desired.contacts.push(contact.clone());
    }
    desired.validate()?;
    Ok(desired)
}

fn validate_committed(job: &Attachment, committed: &RuntimeConfig, outcome: &Value) -> Result<()> {
    let destination = outcome["destination_digest"]
        .as_str()
        .ok_or_else(|| local("HOST_REBIND_STATE_INVALID"))?;
    if outcome["state"] != "HOST_REBIND_READY" {
        return Err(local("HOST_REBIND_NOT_COMMITTED"));
    }
    let mut expected = job.owned.as_ref().ok_or_else(||local("ORIGINAL_RUNTIME_CONFIG_REQUIRED"))?.config.clone();
    if let Some(subscriptions) = &job.request.initial_subscriptions {
        expected
            .hosts
            .push(crate::participant_dispatch::HostConfig {
                name: job.request.host.clone(),
                adapter: job.request.adapter.clone(),
                subscriptions: subscriptions.clone(),
            });
    }
    let host = expected
        .hosts
        .iter_mut()
        .find(|h| h.name == job.request.host)
        .ok_or_else(|| local("HOST_REBIND_STATE_INVALID"))?;
    host.adapter = job.request.adapter.clone();
    for subscription in &mut host.subscriptions {
        subscription.watch.host_destination = Some(destination.into());
    }
    if serde_json::to_value(expected).ok() != serde_json::to_value(committed).ok() {
        return Err(local("ORIGINAL_RUNTIME_CONFIG_CHANGED"));
    }
    Ok(())
}

impl Connect {
    /// One explicit local selection; ordinary MCP requests cannot supply paths,
    /// process IDs or administrative authority. This names the selected session,
    /// not an assertion that a generic MCP caller owns that exact thread.
    pub async fn attach_codex(
        &mut self,
        request: ConnectRequest,
        chat: Option<&str>,
    ) -> Result<Value> {
        self.attach_codex_with_runtime(request,chat,None).await
    }
    pub async fn attach_codex_with_runtime(&mut self,request:ConnectRequest,chat:Option<&str>,selection:Option<RuntimeSelection>)->Result<Value> {
        self.require_writer()?;
        let key = format!("{}:{}", request.participant, request.workspace_id);
        if let Some(job) = self.registry.codex_attachments.get(&key).cloned() {
            if chat.is_none_or(|c| c == job.selected_chat || job.request.adapter["thread_id"] == c)
            {
                if request != job.invocation {
                    return Err(local("CODEX_ATTACHMENT_SELECTION_CHANGED_RESUME_ORIGINAL"));
                }
                return self.resume_codex(&key, job).await;
            }
            if !job.finished {
                return Err(local("CODEX_ATTACHMENT_PENDING_RESUME_ORIGINAL_CHAT"));
            }
            // Its sealed rebind evidence remains in the original ledger; only
            // a new explicit chat selection starts the next attachment.
        }
        let executable = crate::communication_host::codex_executable(None).map_err(failure)?;
        let config = json!({"endpoint":"codex-proxy://local","codex_executable":executable});
        let executor = tokio::runtime::Handle::current();
        let sessions = tokio::task::spawn_blocking(move || {
            crate::communication_host::codex_sessions(config, executor)
        })
        .await
        .map_err(|_| local("HOST_DISCOVERY_FAILED"))?
        .map_err(failure)?;
        let Some(chat) = chat else {
            return Ok(
                json!({"state":"PENDING","blocker":{"stage":"HOST_SELECTION","code":"CODEX_CHAT_SELECTION_REQUIRED",
                "next_actor":"LOCAL_USER","next_action":"SELECT_EXISTING_CODEX_CHAT_TITLE"},"sessions":sessions["sessions"],
                "next_cursor":sessions["next_cursor"],"existing_receiver_preserved":true}),
            );
        };
        let mut adapter = select_session(&sessions, chat)?;
        adapter["codex_executable"] = json!(executable);
        self.attach_selected_codex(request, adapter, chat, selection).await
    }
    /// Reuse a host-owner registered native/bridge destination without opening
    /// that user's control socket or copying signer credentials across users.
    pub async fn attach_codex_host(
        &mut self,
        request: ConnectRequest,
        name: &str,
    ) -> Result<Value> {
        self.attach_codex_host_with_runtime(request,name,None).await
    }
    pub async fn attach_codex_host_with_runtime(&mut self,request:ConnectRequest,name:&str,selection:Option<RuntimeSelection>)->Result<Value> {
        self.require_writer()?;
        let key = format!("{}:{}", request.participant, request.workspace_id);
        if let Some(job) = self.registry.codex_attachments.get(&key).cloned() {
            if job.selected_chat == name {
                if job.invocation != request {
                    return Err(local("CODEX_ATTACHMENT_SELECTION_CHANGED_RESUME_ORIGINAL"));
                }
                return self.resume_codex(&key, job).await;
            }
            if !job.finished {
                return Err(local("CODEX_ATTACHMENT_PENDING_RESUME_ORIGINAL_CHAT"));
            }
        }
        let host = self
            .registry
            .hosts
            .get(name)
            .filter(|h| h.participant == request.participant)
            .ok_or_else(|| local("REGISTERED_CODEX_HOST_REQUIRED"))?;
        if host.adapter["kind"] != "codex"
            && !(host.adapter["kind"] == "bridge"
                && host.adapter["destination"]["host"] == "CODEX_APP_SERVER")
        {
            return Err(local("REGISTERED_CODEX_HOST_REQUIRED"));
        }
        self.attach_selected_codex(request, host.adapter.clone(), name, selection)
            .await
    }
    async fn attach_selected_codex(
        &mut self,
        request: ConnectRequest,
        adapter: Value,
        chat: &str,
        selection: Option<RuntimeSelection>,
    ) -> Result<Value> {
        let key = format!("{}:{}", request.participant, request.workspace_id);
        self.original_client(&request.participant).await?;
        let setup = self
            .registry
            .active_by_scope
            .get(&key)
            .and_then(|id| self.registry.setups.get(id))
            .filter(|s| {
                s.channel_receive
                    && s.profile
                        .as_ref()
                        .is_some_and(|p| p.receive_endpoint_path.is_some())
            })
            .cloned();
        let Some(setup) = setup else {
            // No existing receiver to transfer. Reuse normal permission and
            // profile setup; rights already held need no Owner exchange.
            let name = format!(
                "codex-{}",
                &sha256_hex(adapter.to_string().as_bytes())[..24]
            );
            let admin=self.runtime_admin(&request.participant,selection.as_ref()).await?;
            let status=crate::communication_runtime::call(&admin,json!({"method":"status"})).await?;
            let receivers=status["value"]["receivers"].as_array().ok_or_else(||local("RECEIVER_INVENTORY_UNAVAILABLE_USE_ORIGINAL_SETUP"))?;
            if receivers.iter().any(|r|self.registry.verified_bindings.get(&request.participant).is_some_and(|binding|["actor_id","origin","engine_digest","state_binding"].iter().all(|field|r[*field]==binding[*field]))&&r["bindings"].as_array().is_some_and(|items|items.iter().any(|w|w["workspace_id"]==request.workspace_id))) {
                return Err(local("ORIGINAL_RECEIVER_SETUP_RECOVERY_REQUIRED"));
            }
            self.register_host(
                &name,
                host::HostSelection {
                    participant: request.participant.clone(),
                    admin_endpoint: admin,
                    adapter,
                },
            )
            .await?;
            let mut request = request;
            request.receive = true;
            request.receive_mode = Some(ReceiveMode::Push);
            request.host = Some(name);
            return self.run_agent(request).await;
        };
        if setup
            .effective_host
            .as_ref()
            .and_then(|name| self.registry.hosts.get(name))
            .is_some_and(|h| h.adapter == adapter)
        {
            let changed = request.management.iter().any(|operation|!setup.desired.management.contains(operation))
                || request.send && !setup.desired.send
                || request.require_body_keys && !setup.desired.require_body_keys
                || request.request_membership && !setup.desired.request_membership
                || request
                    .protocols
                    .iter()
                    .any(|p| !setup.desired.protocols.contains(p))
                || request
                    .contacts
                    .iter()
                    .any(|c| !setup.desired.contacts.contains(c));
            if !changed {
                return self.run_agent(setup.desired).await;
            }
            let host = setup.effective_host.as_deref().unwrap();
            let desired = desired_setup(
                &setup.desired,
                &request,
                host,
                &json!([setup.desired, request, adapter]).to_string(),
            )?;
            return self.run_agent(desired).await;
        }
        let admin=self.runtime_admin(&request.participant,selection.as_ref()).await?;
        let runtime_status=crate::communication_runtime::call(&admin,json!({"method":"status"})).await?;
        let resident=runtime_status["value"]["optional_features"].as_array().is_some_and(|features|features.iter().any(|feature|feature=="resident-scope-rebind-v1"));
        let owned=if resident {
            // An explicitly supplied legacy config must not contradict the
            // original client, even though live rebind does not need the file.
            if selection.as_ref().is_some_and(|s|s.config_path.is_some()){self.runtime_for_attachment(&request.participant,selection.as_ref()).await?;}
            None
        }else{Some(self.runtime_for_attachment(&request.participant,selection.as_ref()).await?)};
        let profile = setup.profile.as_ref().unwrap();
        let receiver = RuntimeClient::connect(
            profile.receive_endpoint_path.clone().unwrap(),
            &profile.expected_origin,
            &profile.expected_actor,
        )
        .await?;
        let binding = receiver.call(json!({"method":"binding"})).await?;
        crate::communication_runtime::validate_binding(
            &binding,
            &profile.expected_origin,
            &profile.expected_actor,
        )?;
        let name = binding["client_name"]
            .as_str()
            .filter(|s| identifier(s))
            .ok_or_else(|| local("LOCAL_RUNTIME_UPGRADE_REQUIRED"))?;
        let watches = receiver.call(json!({"method":"bindings"})).await?;
        let watches: Vec<WatchOptions> =
            serde_json::from_value(watches).map_err(|_| local("RECEIVER_BINDINGS_INVALID"))?;
        let watches: Vec<_> = watches
            .into_iter()
            .filter(|w| {
                w.workspace_id == request.workspace_id
                    && profile
                        .scopes
                        .values()
                        .any(|s| s.mailbox_id == w.mailbox_id && s.membership_id == w.membership_id)
            })
            .collect();
        if watches.len() != 1 {
            return Err(local("RECEIVER_SCOPE_SELECTION_REQUIRED"));
        }
        let watch = watches[0].clone();
        // Authenticated resident metadata identifies the same engine without
        // reconstructing a launch config or reopening its client registry.
        if self.registry.verified_bindings.get(&request.participant).is_none_or(|root|
            root["state_binding"]!=binding["state_binding"]||root["engine_digest"]!=binding["engine_digest"]) {
            return Err(local("ORIGINAL_RECEIVER_BINDING_MISMATCH"));
        }
        let engine=if let Some(owned)=&owned {
            let matches=owned.config.engines.iter().filter(|e|e.expected_actor==profile.expected_actor&&e.binding_digest().ok().as_deref()==binding["engine_digest"].as_str()).collect::<Vec<_>>();
            if matches.len()!=1{return Err(local("ORIGINAL_RECEIVER_BINDING_MISMATCH"));}matches[0].name.clone()
        }else{
            let matches=runtime_status["value"]["engines"].as_array().ok_or_else(||local("HOST_RUNTIME_BINDING_MISMATCH"))?.iter()
                .filter(|e|["actor_id","origin","state_binding","engine_digest"].iter().all(|field|e[*field]==binding[*field])).collect::<Vec<_>>();
            if matches.len()!=1{return Err(local("ORIGINAL_RECEIVER_BINDING_MISMATCH"));}
            matches[0]["name"].as_str().ok_or_else(||local("HOST_RUNTIME_BINDING_MISMATCH"))?.to_owned()
        };
        let generation=binding["client_generation"].as_u64();
        let host=if watch.host_destination.is_some() {
            if let Some(owned)=&owned {
                let matches=owned.config.hosts.iter().filter(|h|h.subscriptions.iter().any(|source|source.client==name&&source.client_generation==generation&&source.watch==watch)).collect::<Vec<_>>();
                if matches.len()!=1||matches[0].subscriptions.len()!=1{return Err(local("HOST_GROUP_SELECTION_REQUIRED"));}matches[0].name.clone()
            }else{
                let matches=runtime_status["value"]["hosts"].as_array().ok_or_else(||local("HOST_GROUP_SELECTION_REQUIRED"))?.iter().filter(|host|
                    host["source_bindings"].as_array().is_some_and(|sources|sources.iter().any(|source|source["client"]==name&&source["client_generation"].as_u64()==generation&&serde_json::from_value::<WatchOptions>(source["watch"].clone()).ok().as_ref()==Some(&watch)))).collect::<Vec<_>>();
                if matches.len()!=1||matches[0]["source_bindings"].as_array().is_none_or(|sources|sources.len()!=1){return Err(local("HOST_GROUP_SELECTION_REQUIRED"));}
                matches[0]["source_name"].as_str().ok_or_else(||local("HOST_GROUP_SELECTION_REQUIRED"))?.to_owned()
            }
        }else{format!("codex-{}",&sha256_hex(key.as_bytes())[..24])};
        let operation_id = format!(
            "attach-{}",
            &sha256_hex(json!([key, binding, adapter, watch]).to_string().as_bytes())[..40]
        );
        let desired = desired_setup(&setup.desired, &request, &host, &operation_id)?;
        let invocation = request.clone();
        let job = Attachment {
            setup_id: setup.desired.setup_id.clone(),
            selected_chat: chat.into(),
            desired,
            invocation,
            owned,
            resident_admin:resident.then_some(admin),
            source_binding: binding.clone(),
            committed: None,
            finished: false,
            aborted: false,
            request: HostRebindRequest {
                format: "peerwork.host-rebind.v1".into(),
                operation_id,
                engine,
                host,
                adapter,
                initial_subscriptions: if watch.host_destination.is_some() {
                    None
                } else {
                    Some(vec![HostSubscription {
                        client: name.into(),
                        client_generation: generation,
                        watch,
                    }])
                },
            },
        };
        if self.registry.codex_attachments.len() >= 64 {
            return Err(local("LOCAL_ATTACHMENT_LIMIT"));
        }
        self.registry
            .codex_attachments
            .insert(key.clone(), job.clone());
        self.save()?;
        self.resume_codex(&key, job).await
    }
    async fn resume_codex(&mut self, key: &str, job: Attachment) -> Result<Value> {
        self.resume_codex_with_recovery(key,job,None).await
    }
    /// A decision continues the stored attachment; it cannot discover/create a
    /// new destination or replace the original request after an unknown claim.
    pub async fn recover_codex_attachment(&mut self,request:ConnectRequest,selected_chat:Option<&str>,decision:crate::participant_rebind::HostRebindRecoveryRequest)->Result<Value>{
        self.require_writer()?;
        if decision.format!="peerwork.host-rebind-recovery.v1"||!identifier(&decision.decision_id){return Err(local("HOST_REBIND_RECOVERY_SELECTION_INVALID"));}
        let key=format!("{}:{}",request.participant,request.workspace_id);
        let job=self.registry.codex_attachments.get(&key).cloned().ok_or_else(||local("ORIGINAL_CODEX_ATTACHMENT_REQUIRED"))?;
        if request!=job.invocation{return Err(local("CODEX_ATTACHMENT_SELECTION_CHANGED_RESUME_ORIGINAL"));}
        if selected_chat.is_some_and(|selected|selected!=job.selected_chat&&job.request.adapter["thread_id"]!=selected){return Err(local("CODEX_ATTACHMENT_SELECTION_CHANGED_RESUME_ORIGINAL"));}
        self.resume_codex_with_recovery(&key,job,Some(decision)).await
    }
    fn attachment_aborted(job:&Attachment)->Value{
        json!({"state":"ABORTED","operation_id":job.request.operation_id,"recovery":"OBSERVE_ORIGINAL_RECEIVER",
            "existing_state_preserved":true,"model_response":"NOT_ATTESTED","tools_available":true})
    }
    async fn resume_codex_with_recovery(&mut self,key:&str,mut job:Attachment,recovery:Option<crate::participant_rebind::HostRebindRecoveryRequest>)->Result<Value>{
        if job.aborted{return Ok(Self::attachment_aborted(&job));}
        let mut runtime_restarted=false;
        if let Some(admin)=&job.resident_admin {
            self.adopt(&job.invocation.participant).await?;
            let mut call=json!({"method":"host_rebind","rebind":job.request});
            if let Some(recovery)=recovery {call["recovery"]=json!(recovery);}
            let outcome=crate::communication_runtime::call(admin,call).await?;
            if outcome["ok"]!=true {let error:crate::participant::ParticipantError=serde_json::from_value(outcome["error"].clone()).map_err(|_|local("HOST_REBIND_STATE_INVALID"))?;
                return Ok(json!({"state":"PENDING","operation_id":job.request.operation_id,"effect_certainty":error.effect_certainty,"recovery":"RESUME_SAME_ATTACHMENT","blocker":{"stage":"HOST_BINDING","code":error.code,"next_actor":"LOCAL_RUNTIME_OWNER","next_action":"INSPECT_OR_RESUME_ORIGINAL_HOST_BINDING"},"error":error,"tools_available":true,"existing_state_preserved":true}));}
            let value=&outcome["value"];
            if value["operation_id"]!=job.request.operation_id{return Err(local("HOST_REBIND_STATE_INVALID"));}
            if value["state"]=="HOST_REBIND_ABORTED"{
                job.aborted=true;job.finished=true;
                self.registry.codex_attachments.insert(key.into(),job.clone());self.save()?;
                return Ok(Self::attachment_aborted(&job));
            }
            if value["state"]!="HOST_REBIND_READY" {
                let decision_required=value["blocker"]["recovery"]=="EXPLICIT_HOST_REBIND_RECOVERY_DECISION_REQUIRED";
                return Ok(json!({"state":"PENDING","operation_id":job.request.operation_id,"effect_certainty":value["blocker"].get("effect_certainty").cloned().unwrap_or(json!("UNKNOWN")),"recovery":"RESUME_SAME_ATTACHMENT","blocker":{"stage":"HOST_BINDING","code":value["blocker"].get("code").cloned().unwrap_or(json!("HOST_REBIND_IN_PROGRESS")),"next_actor":if decision_required{"LOCAL_RUNTIME_OWNER"}else{"RUNTIME"},"next_action":if decision_required{"REPEAT_ORIGINAL_CONNECT_WITH_BINDING_RECOVERY_AND_STABLE_DECISION_ID"}else{"RESUME_SAME_CODEX_ATTACHMENT"}},"runtime_restarted":false,"tools_available":true,"existing_state_preserved":true,"binding_operation":value}));
            }
        }else{
            if recovery.is_some(){return Err(local("RESIDENT_ATTACHMENT_RECOVERY_REQUIRED_USE_ORIGINAL_OFFLINE_RECOVERY"));}
            let owned=job.owned.clone().ok_or_else(||local("ORIGINAL_RUNTIME_CONFIG_REQUIRED"))?;
        if job.committed.is_none() {
            // A rebind may have committed before its response was saved. The
            // sealed rebind job recognizes that case with the original ID.
            let result = async {
                let current: RuntimeConfig = serde_json::from_value(
                    crate::communication_store::private_json(&owned.path(), 65536)
                        .map_err(|_| local("RUNTIME_CONFIG_NOT_PRIVATE"))?,
                )
                .map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
                owned.same_engine(&current)?;
                if serde_json::to_value(&current).ok()
                    == serde_json::to_value(&owned.config).ok()
                {
                    owned.stop().await?;
                    let client_name = job.source_binding["client_name"]
                        .as_str()
                        .ok_or_else(|| local("ORIGINAL_RECEIVER_BINDING_MISMATCH"))?;
                    let source = crate::communication_runtime::rebind_client(
                        &owned.config,
                        client_name,
                    )?;
                    if source.namespace != job.source_binding["namespace"]
                        || source.generation != job.source_binding["client_generation"].as_u64()
                    {
                        return Err(local("ORIGINAL_RECEIVER_BINDING_MISMATCH"));
                    }
                }
                let outcome =
                    crate::participant_rebind::rebind_host(&owned.path(), job.request.clone())
                        .await?;
                let committed: RuntimeConfig = serde_json::from_value(
                    crate::communication_store::private_json(&owned.path(), 65536)
                        .map_err(|_| local("RUNTIME_CONFIG_NOT_PRIVATE"))?,
                )
                .map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
                owned.same_engine(&committed)?;
                validate_committed(&job, &committed, &outcome)?;
                Ok(committed)
            }
            .await;
            match result {
                Ok(config) => {
                    job.committed = Some(config);
                    self.registry
                        .codex_attachments
                        .insert(key.into(), job.clone());
                    self.save()?;
                }
                Err(error) => {
                    return Ok(
                        json!({"state":"PENDING","operation_id":job.request.operation_id,"effect_certainty":"UNKNOWN","recovery":"RESUME_SAME_ATTACHMENT","blocker":{"stage":"HOST_BINDING","code":error.code,"next_action":"RESUME_SAME_CODEX_ATTACHMENT"},"error":error,"existing_state_preserved":true}),
                    )
                }
            }
        }
        let launch_before=SecureStateStore::read_snapshot(&owned.config.state_directory.join("bootstrap.state"),65536).ok();
        if let Err(error) = owned.restart(job.committed.as_ref().unwrap()).await {
            return Ok(
                json!({"state":"PENDING","operation_id":job.request.operation_id,"effect_certainty":"UNKNOWN","recovery":"RESUME_SAME_ATTACHMENT","blocker":{"stage":"RUNTIME_RESTART","code":error.code,"next_action":"RESUME_SAME_CODEX_ATTACHMENT"},"error":error,"existing_state_preserved":true}),
            );
        }
        runtime_restarted=launch_before!=SecureStateStore::read_snapshot(&owned.config.state_directory.join("bootstrap.state"),65536).ok();
        }
        let setup = self
            .registry
            .setups
            .get(&job.setup_id)
            .cloned()
            .ok_or_else(|| local("ORIGINAL_SETUP_REQUIRED"))?;
        let profile = setup
            .profile
            .as_ref()
            .ok_or_else(|| local("ORIGINAL_SETUP_REQUIRED"))?;
        let receiver = RuntimeClient::connect(
            profile
                .receive_endpoint_path
                .clone()
                .ok_or_else(|| local("ORIGINAL_SETUP_REQUIRED"))?,
            &profile.expected_origin,
            &profile.expected_actor,
        )
        .await?;
        let current = receiver.call(json!({"method":"binding"})).await?;
        if [
            "namespace",
            "client_name",
            "client_generation",
            "state_binding",
            "engine_digest",
        ]
        .iter()
        .any(|field| current[field] != job.source_binding[field])
        {
            return Err(local("ORIGINAL_RECEIVER_BINDING_MISMATCH"));
        }
        let selected = HostSelection {
            participant: setup.desired.participant.clone(),
            admin_endpoint: job.resident_admin.clone().or_else(||job.owned.as_ref().map(|owned|owned.config.state_directory.join("admin.json"))).ok_or_else(||local("EXPLICIT_RUNTIME_ADMIN_SELECTION_REQUIRED"))?,
            adapter: job.request.adapter.clone(),
        };
        // Same named host can legitimately have a committed replacement; its
        // new config is the sealed rebind outcome, never a model-supplied edit.
        self.registry
            .hosts
            .insert(job.request.host.clone(), selected);
        // Preserve the old INBOX setup as historical evidence. The new setup
        // reuses its completed receiver through completed_host_binding; missing
        // send/key/role rights use the existing consolidated approval path.
        job.finished = true;
        self.registry
            .codex_attachments
            .insert(key.into(), job.clone());
        self.save()?;
        let mut result = self.run_agent(job.desired.clone()).await?;
        result["operation_id"] = json!(job.request.operation_id);
        result["host_selection"] = json!({"basis":"EXPLICIT_LOCAL_SELECTION","thread_id":job.request.adapter.get("thread_id").unwrap_or(&job.request.adapter["destination"]["conversation_id"]),"session_id":job.request.adapter.get("expected_session_id").unwrap_or(&job.request.adapter["destination"]["session_id"])});
        result["model_response"] = json!("NOT_ATTESTED");
        result["runtime_restarted"]=json!(runtime_restarted);
        result["binding_mode"]=json!(if job.resident_admin.is_some(){"RESIDENT"}else{"OFFLINE"});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_chat_selection_does_not_guess_latest_or_confuse_parent_and_child() {
        let sessions = json!({"sessions":[{"thread_id":"parent","session_id":"parent","title":"Master"},{"thread_id":"child","session_id":"parent","title":"Worker"}]});
        let child = select_session(&sessions, "Worker").unwrap();
        assert_eq!(child["thread_id"], "child");
        assert_eq!(child["expected_session_id"], "parent");
        assert_eq!(
            select_session(&sessions, "latest").unwrap_err().code,
            "CODEX_CHAT_NOT_LOADED"
        );
        let duplicate = json!({"sessions":[{"thread_id":"one","title":"Worker"},{"thread_id":"two","title":"Worker"}]});
        assert_eq!(
            select_session(&duplicate, "Worker").unwrap_err().code,
            "CODEX_CHAT_TITLE_AMBIGUOUS"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires local TEST PostgreSQL, HTTP service and freshly built native CLI"]
    async fn native_codex_attachment_preserves_original_receiver_and_reuses_committed_config() {
        for runtime_mode in ["connect", "explicit", "published"] {
            if runtime_mode=="published" && std::env::var_os("PEERWORK_PREVIOUS_PARTICIPANT_CLI").is_none(){continue;}
        use crate::{
            communication_host::{tests::codex_proxy_fixture, write_private},
            communication_runtime as ipc,
            participant::http_tests::{
                configuration, install_synthetic_key, mutate, native_message, selected, Service,
            },
            participant::{ParticipantClient, Scope},
        };
        use std::time::Duration;
        let service = Service::start();
        let root = crate::test_support::protected_test_dir();
        let options = configuration(root.path(), &service.origin);
        let owner = ParticipantClient::open(options.clone()).await.unwrap();
        let ws = mutate(
            &owner,
            "attach-space",
            "structure.workspace.create",
            &Scope::default(),
            json!({"name":"Synthetic Codex attachment"}),
        )
        .await["workspace_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let scope = Scope {
            workspace_id: Some(ws.clone()),
            ..Default::default()
        };
        let metadata = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
        let mailbox=mutate(&owner,"attach-grant","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":metadata["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
        let key = install_synthetic_key(&options, &ws, &[71; 32], None);
        mutate(
            &owner,
            "attach-key",
            "structure.content-key.set",
            &scope,
            json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
        )
        .await;
        let sent = owner
            .invoke(
                native_message(
                    "original-send",
                    &scope,
                    &mailbox,
                    &mailbox,
                    &"T".repeat(43),
                    "original encrypted message",
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(sent.state, "ACCEPTED");
        let workspaces_before_pending=service.counts().await["workspaces"].as_u64().unwrap();
        service.config(json!({"drop_action":"structure.workspace.create"})).await;
        let original_pending=owner.invoke(crate::participant::Invoke::new("original-pending","structure.workspace.create",Scope::default(),json!({"name":"Uncertain original operation"})),Duration::from_secs(1)).await.unwrap();
        assert!(!original_pending.is_terminal(),"fault must leave a genuine original pending operation");
        owner.close().await.unwrap();
        service.config(json!({"offline":false})).await;
        let identity_before = sha256_hex(&std::fs::read(&options.identity_path).unwrap());
        let local = root.path().join("connect");
        let executable = PathBuf::from(std::env::var("PEERWORK_PARTICIPANT_CLI").unwrap());
        let engine = crate::communication_runtime::EngineConfig {
            name: "original".into(),
            origin: options.origin.clone(),
            expected_actor: options.expected_actor.clone(),
            identity_path: options.identity_path.clone(),
            state_directory: options.state_directory.clone(),
            journal_path: Some(options.journal_path.clone()),
            authority: options.authority.clone(),
            allow_loopback_http: true,
            transport: options.transport.clone(),
            max_inflight: 4,
            max_pending: 16,
            max_stored_bytes: 8 * 1024 * 1024,
            migration_sources: vec![],
        };
        let external=runtime_mode!="connect";
        let runtime_dir=if external{root.path().join("original-runtime")}else{local.join("runtime-worker")};
        let config_path=if external{root.path().join("original-runtime-selection.json")}else{runtime_dir.join("config.json")};
        let _original_process=if external {
            let config=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:runtime_dir.clone(),engines:vec![engine.clone()],clients:vec![ipc::ClientConfig{name:"original".into(),engine:engine.name.clone(),capability:Capability::owner()}],hosts:vec![]};
            write_private(&config_path,&serde_json::to_vec(&config).unwrap()).unwrap();
            let original_cli=if runtime_mode=="published"{PathBuf::from(std::env::var("PEERWORK_PREVIOUS_PARTICIPANT_CLI").unwrap())}else{executable.clone()};
            let mut child=tokio::process::Command::new(original_cli).args(["runtime","run"]).arg(&config_path).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().unwrap();
            tokio::time::timeout(Duration::from_secs(10),async{loop{
                if RuntimeClient::connect(runtime_dir.join("client-original.json"),&service.origin,&options.expected_actor).await.is_ok(){break;}
                assert!(child.try_wait().unwrap().is_none(),"original runtime failed");
                tokio::time::sleep(Duration::from_millis(30)).await;
            }}).await.unwrap();Some(child)
        }else{None};
        let engine_file = root.path().join("engine.json");
        write_private(&engine_file, &serde_json::to_vec(&engine).unwrap()).unwrap();
        let (_proxy_path, proxy_fixture) = codex_proxy_fixture(root.path());
        async fn run(executable: &Path, args: &[String], directory: &Path) -> Value {
            let mut command = tokio::process::Command::new(executable);
            command
                .args(args)
                .env(
                    "PATH",
                    format!("{}:/usr/local/bin:/usr/bin:/bin", directory.display()),
                )
                .kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(60), command.output())
                .await
                .expect("synthetic native attachment deadlocked")
                .unwrap();
            let value: Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
            assert_eq!(
                output.status.code(),
                Some(match value["state"].as_str() {
                    Some("PENDING") => 2,
                    Some("FAILED") => 1,
                    _ => 0,
                }),
                "{value}"
            );
            value
        }
        struct Stop {
            cli: PathBuf,
            admin: PathBuf,
        }
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = std::process::Command::new(&self.cli)
                    .args(["runtime", "admin"])
                    .arg(&self.admin)
                    .arg("stop")
                    .output();
            }
        }
        let _stop = Stop {
            cli: executable.clone(),
            admin: runtime_dir.join("admin.json"),
        };
        let base: Vec<String> = vec![
            "connect".into(),
            "--local".into(),
            local.to_str().unwrap().into(),
            "--participant".into(),
            "worker".into(),
            "--workspace".into(),
            ws.clone(),
        ];
        if external {
            let mut cold=base.clone();cold.extend(["--runtime-config".into(),config_path.to_str().unwrap().into(),"--codex".into()]);
            let choice=run(&executable,&cold,root.path()).await;
            assert_eq!(choice["blocker"]["code"],"CODEX_CHAT_SELECTION_REQUIRED","{choice}");
            assert_eq!(Connect::inspect(&local).unwrap().registry.participants["worker"].endpoint_path,runtime_dir.join("client-original.json"));
            assert!(!runtime_dir.join("bootstrap.state").exists());
        }
        let mut initial = base.clone();
        if external{initial.extend(["--client".into(),runtime_dir.join("client-original.json").to_str().unwrap().into(),"--origin".into(),service.origin.clone(),"--actor".into(),options.expected_actor.clone()]);}
        else{initial.extend(["--engine-config".into(),engine_file.to_str().unwrap().into()]);}
        initial.extend(["--id".into(),"original-inbox".into(),"--send".into(),"--receive".into(),"--receive-mode".into(),"inbox".into()]);
        let configured = run(&executable, &initial, root.path()).await;
        assert_eq!(configured["state"], "LOCAL_CONFIGURED", "{configured}");
        let profile = Connect::inspect(&local)
            .unwrap()
            .profile()
            .unwrap()
            .unwrap();
        let endpoint = profile.receive_endpoint_path.clone().unwrap();
        let receiver =
            RuntimeClient::connect(endpoint.clone(), &service.origin, &options.expected_actor)
                .await
                .unwrap();
        let before = receiver.call(json!({"method":"binding"})).await.unwrap();
        let before_config = crate::communication_store::private_json(
            &config_path,
            65536,
        )
        .unwrap();
        let mut attach = base;
        attach.push("--codex".into());
        let choices = run(&executable, &attach, root.path()).await;
        assert_eq!(choices["blocker"]["code"], "CODEX_CHAT_SELECTION_REQUIRED");
        assert_eq!(choices["sessions"].as_array().unwrap().len(), 1);
        fn launch_bytes(directory:&Path)->Vec<u8>{if !directory.join("bootstrap.state").exists(){Vec::new()}else{SecureStateStore::read_snapshot(&directory.join("bootstrap.state"),65536).unwrap().to_vec()}}
        let original_launch=launch_bytes(&runtime_dir);
        attach.extend(["--codex-chat".into(), "Worker".into()]);
        // An endpoint alone is not authority to stop an external runtime.
        {
            let mut registry = Connect::open(&local).unwrap();
            registry.registry.local_runtime_admins.remove("worker");
            registry.save().unwrap();
        }
        let denied = run(&executable, &attach, root.path()).await;
        assert_eq!(
            denied["error"]["code"], "EXPLICIT_RUNTIME_ADMIN_SELECTION_REQUIRED",
            "{denied}"
        );
        assert!(
            receiver.call(json!({"method":"binding"})).await.is_ok(),
            "unknown owner was stopped"
        );
        if external {
            // No Connect receipt, non-default config path and original client name.
            assert!(!runtime_dir.join("bootstrap.state").exists());
            let mut wrong:Value=serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
            wrong["engines"][0]["journal_path"]=json!(root.path().join("wrong-journal.sqlite"));
            let wrong_file=root.path().join("wrong-runtime.json");write_private(&wrong_file,&serde_json::to_vec(&wrong).unwrap()).unwrap();
            let mut denied=attach.clone();denied.extend(["--runtime-config".into(),wrong_file.to_str().unwrap().into()]);
            assert_eq!(run(&executable,&denied,root.path()).await["error"]["code"],"ORIGINAL_RUNTIME_CONFIG_MISMATCH");
            assert!(receiver.call(json!({"method":"binding"})).await.is_ok());
            attach.extend(["--runtime-config".into(),config_path.to_str().unwrap().into()]);
        }else{
            let mut registry = Connect::open(&local).unwrap();
            registry.registry.local_runtime_admins.insert("worker".into(),runtime_dir.join("admin.json"));registry.save().unwrap();
        }
        let mut premature=attach.clone();premature.extend(["--binding-recovery".into(),"RETRY_REJECTED".into(),"--decision-id".into(),"not-a-new-attachment".into()]);
        assert_eq!(run(&executable,&premature,root.path()).await["error"]["code"],"ORIGINAL_CODEX_ATTACHMENT_REQUIRED");
        let mut result = run(&executable, &attach, root.path()).await;
        for _ in 0..20 {
            if result["state"] == "LOCAL_CONFIGURED" {
                break;
            }
            assert_eq!(result["state"], "PENDING", "{result}");
            tokio::time::sleep(Duration::from_millis(100)).await;
            result = run(&executable, &attach, root.path()).await;
        }
        assert_eq!(result["state"], "LOCAL_CONFIGURED", "{result}");
        assert_eq!(result["receive_mode"], "PUSH");
        assert_eq!(result["owner_exchange_required"], false);
        assert_eq!(result["host_selection"]["thread_id"], "existing-thread");
        assert_eq!(result["model_response"], "NOT_ATTESTED");
        let new_profile = Connect::inspect(&local)
            .unwrap()
            .profile()
            .unwrap()
            .unwrap();
        assert_eq!(new_profile.receive_endpoint_path, Some(endpoint.clone()));
        let tools = crate::agent_tools::AgentTools::open(new_profile.clone())
            .await
            .unwrap();
        let context = tools
            .call(crate::agent_tools::AgentRequest::Context)
            .await
            .unwrap();
        assert_eq!(
            context["receiving_binding"]["namespace"],
            before["namespace"]
        );
        let receiver = RuntimeClient::connect(endpoint, &service.origin, &options.expected_actor)
            .await
            .unwrap();
        let after = receiver.call(json!({"method":"binding"})).await.unwrap();
        for field in [
            "namespace",
            "client_name",
            "client_generation",
            "engine_digest",
            "state_binding",
        ] {
            assert_eq!(before[field], after[field], "{field}");
        }
        let new_config = crate::communication_store::private_json(
            &config_path,
            65536,
        )
        .unwrap();
        assert_eq!(before_config["engines"], new_config["engines"]);
        assert_eq!(before_config["clients"], new_config["clients"]);
        let launch=launch_bytes(&runtime_dir);
        if runtime_mode=="published" {assert_ne!(launch,original_launch);assert_eq!(result["runtime_restarted"],true);}
        else {assert_eq!(launch,original_launch,"resident binding must keep the original process");assert_eq!(result["runtime_restarted"],false);}

        let repeated = run(&executable, &attach, root.path()).await;
        assert_eq!(repeated["state"], "LOCAL_CONFIGURED", "{repeated}");
        assert_eq!(
            launch_bytes(&runtime_dir).as_slice(),
            launch.as_slice(),
            "reentry must not restart again"
        );
        // Lose only the outer completion save; the sealed rebind remains final.
        {
            let mut registry = Connect::open(&local).unwrap();
            let job = registry
                .registry
                .codex_attachments
                .get_mut(&format!("worker:{ws}"))
                .unwrap();
            job.committed = None;
            job.finished = false;
            registry.save().unwrap();
        }
        let recovered = run(&executable, &attach, root.path()).await;
        assert_eq!(recovered["state"], "LOCAL_CONFIGURED", "{recovered}");
        assert_eq!(recovered["operation_id"], result["operation_id"]);
        assert_eq!(
            launch_bytes(&runtime_dir).as_slice(),
            launch.as_slice()
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let inputs = proxy_fixture
                    .calls()
                    .iter()
                    .filter(|v| matches!(v["method"].as_str(), Some("turn/start" | "turn/steer")))
                    .count();
                if inputs == 1 {
                    break;
                }
                assert!(inputs <= 1, "duplicate model input");
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            service.counts().await["claim_commands"]
                .as_array()
                .unwrap()
                .len(),
            2,
            "one original and one replacement claim only"
        );
        assert_eq!(
            service.counts().await["actions"]["structure.communication.grant.set"],
            1
        );
        assert_eq!(
            sha256_hex(&std::fs::read(&options.identity_path).unwrap()),
            identity_before
        );
        ipc::call(&_stop.admin, json!({"method":"stop"}))
            .await
            .unwrap();
        let restored = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match ParticipantClient::open(options.clone()).await {
                    Ok(v) => break v,
                    Err(_) => tokio::time::sleep(Duration::from_millis(30)).await,
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            restored
                .operation("original-send")
                .await
                .unwrap()
                .command_id,
            sent.command_id
        );
        let original=restored.operation("original-pending").await.unwrap();
        if let Some(command)=original_pending.command_id {assert_eq!(original.command_id.as_deref(),Some(command.as_str()));}
        let completed=crate::participant::http_tests::wait_terminal(&restored,"original-pending").await;
        assert_eq!(completed.state,"ACCEPTED");
        assert_eq!(service.counts().await["workspaces"].as_u64().unwrap(),workspaces_before_pending+1,"the original uncertain create must not be replaced");
        restored.close().await.unwrap();
        assert_eq!(service.counts().await["journal_reads"], 0);
        }
    }
    #[tokio::test(flavor="multi_thread",worker_threads=2)]
    #[ignore="requires local TEST PostgreSQL and real HTTP service"]
    async fn explicit_live_first_attachment_needs_no_restart_and_detects_hidden_receiver() {
        use crate::{communication_runtime as ipc,communication_host::tests::CodexFixture,participant::http_tests::{Service,configuration,mutate,selected,install_synthetic_key},participant::{ParticipantClient,Scope}};
        for hidden_receiver in [false,true] {
            let service=Service::start();let root=crate::test_support::protected_test_dir();let options=configuration(root.path(),&service.origin);
            let owner=ParticipantClient::open(options.clone()).await.unwrap();
            let ws=mutate(&owner,"create","structure.workspace.create",&Scope::default(),json!({"name":"Explicit first connection"})).await["workspace_id"].as_str().unwrap().to_owned();
            let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
            mutate(&owner,"mail","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await;
            let key=install_synthetic_key(&options,&ws,&[48;32],None);mutate(&owner,"key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
            let other_root=crate::test_support::protected_test_dir();let other_options=configuration(other_root.path(),&service.origin);
            let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
            let mut admit=crate::participant::Invoke::new("admit-other","structure.member.set",scope.clone(),json!({"actor_id":other_options.expected_actor,"state":"ACTIVE","expected_membership_id":null}));admit.expected_workspace_revision=meta["workspace_revision"].as_u64();
            let admitted=owner.invoke(admit,std::time::Duration::from_secs(5)).await.unwrap();assert_eq!(admitted.state,"ACCEPTED");
            let other_mailbox=mutate(&owner,"other-mail","structure.communication.grant.set",&scope,json!({"actor_id":other_options.expected_actor,"membership_id":admitted.outcome.as_ref().unwrap()["result"]["structure"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
            owner.close().await.unwrap();
            fn engine(name:&str,c:&crate::participant::ParticipantConfig)->ipc::EngineConfig{ipc::EngineConfig{name:name.into(),origin:c.origin.clone(),expected_actor:c.expected_actor.clone(),identity_path:c.identity_path.clone(),state_directory:c.state_directory.clone(),journal_path:Some(c.journal_path.clone()),authority:None,allow_loopback_http:true,transport:c.transport.clone(),max_inflight:4,max_pending:16,max_stored_bytes:8*1024*1024,migration_sources:vec![]}}
            let runtime=RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),engines:vec![engine("original",&options),engine("other",&other_options)],clients:vec![ipc::ClientConfig{name:"original".into(),engine:"original".into(),capability:Capability::owner()},ipc::ClientConfig{name:"other".into(),engine:"other".into(),capability:Capability::owner()}],hosts:vec![]};
            let cancel=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let serving=tokio::spawn(ipc::serve(runtime.clone(),cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
            let other=RuntimeClient::connect(ready.client_endpoints["other"].clone(),&service.origin,&other_options.expected_actor).await.unwrap();
            other.call(json!({"method":"watch","options":{"workspace_id":ws,"mailbox_id":other_mailbox["mailbox_id"],"membership_id":other_mailbox["membership_id"],"consumer_id":"other-inbox"}})).await.unwrap();
            let mut connect=Connect::open(&root.path().join("connect")).unwrap();connect.register("worker",Registration{origin:service.origin.clone(),actor_id:options.expected_actor.clone(),endpoint_path:ready.client_endpoints["original"].clone()}).await.unwrap();
            let host=CodexFixture::start();connect.register_host("selected",host::HostSelection{participant:"worker".into(),admin_endpoint:ready.admin_endpoint.clone(),adapter:host.config()}).await.unwrap();
            let request:ConnectRequest=serde_json::from_value(json!({"setup_id":"live","participant":"worker","workspace_id":ws,"send":true,"receive":true,"receive_mode":"INBOX"})).unwrap();
            if hidden_receiver {
                assert_eq!(connect.run_agent(request.clone()).await.unwrap()["state"],"LOCAL_CONFIGURED");
                connect.registry.setups.clear();connect.registry.active=None;connect.registry.active_by_scope.clear();connect.save().unwrap();
            }
            let mut request=request;request.receive_mode=Some(ReceiveMode::Push);
            let selection=Some(RuntimeSelection{admin_endpoint:ready.admin_endpoint.clone(),config_path:None});
            let result=connect.attach_codex_host_with_runtime(request,"selected",selection).await;
            if hidden_receiver {assert_eq!(result.unwrap_err().code,"ORIGINAL_RECEIVER_SETUP_RECOVERY_REQUIRED");}
            else {let result=result.unwrap();assert_eq!(result["state"],"LOCAL_CONFIGURED","{result}");assert_eq!(result["receive_mode"],"PUSH");}
            assert!(!serving.is_finished(),"online binding must not restart original runtime");assert!(!runtime.state_directory.join("bootstrap.state").exists());
            cancel.cancel();serving.await.unwrap().unwrap();
        }
    }

}
