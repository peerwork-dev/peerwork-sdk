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
    owned: bootstrap::OwnedRuntime,
    source_binding: Value,
    request: HostRebindRequest,
    committed: Option<RuntimeConfig>,
    #[serde(default)]
    finished: bool,
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
    let mut expected = job.owned.config.clone();
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
        self.attach_selected_codex(request, adapter, chat).await
    }
    /// Reuse a host-owner registered native/bridge destination without opening
    /// that user's control socket or copying signer credentials across users.
    pub async fn attach_codex_host(
        &mut self,
        request: ConnectRequest,
        name: &str,
    ) -> Result<Value> {
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
        self.attach_selected_codex(request, host.adapter.clone(), name)
            .await
    }
    async fn attach_selected_codex(
        &mut self,
        request: ConnectRequest,
        adapter: Value,
        chat: &str,
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
            let admin = self
                .registry
                .local_runtime_admins
                .get(&request.participant)
                .cloned()
                .ok_or_else(|| local("LOCAL_RUNTIME_TAKEOVER_REQUIRED"))?;
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
            let changed = request.send && !setup.desired.send
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
        let owned = bootstrap::owned_runtime(self, &request.participant)?;
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
        // The live runtime owns the client registry. Read its authenticated
        // binding now; resolve the original lineage only AFTER stopping it.
        let engines: Vec<_> = owned
            .config
            .engines
            .iter()
            .filter(|e| {
                e.expected_actor == profile.expected_actor
                    && e.binding_digest().ok().as_deref() == binding["engine_digest"].as_str()
            })
            .collect();
        if engines.len() != 1
            || self
                .registry
                .verified_bindings
                .get(&request.participant)
                .is_none_or(|root| {
                    root["state_binding"] != binding["state_binding"]
                        || root["engine_digest"] != binding["engine_digest"]
                })
        {
            return Err(local("ORIGINAL_RECEIVER_BINDING_MISMATCH"));
        }
        let engine = engines[0].name.clone();
        let generation = binding["client_generation"].as_u64();
        let existing: Vec<_> = owned
            .config
            .hosts
            .iter()
            .filter(|h| {
                h.subscriptions.iter().any(|s| {
                    s.client == name && s.client_generation == generation && s.watch == watch
                })
            })
            .collect();
        let host = if watch.host_destination.is_some() {
            if existing.len() != 1 || existing[0].subscriptions.len() != 1 {
                return Err(local("HOST_GROUP_SELECTION_REQUIRED"));
            }
            existing[0].name.clone()
        } else {
            format!("codex-{}", &sha256_hex(key.as_bytes())[..24])
        };
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
            source_binding: binding.clone(),
            committed: None,
            finished: false,
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
    async fn resume_codex(&mut self, key: &str, mut job: Attachment) -> Result<Value> {
        if job.committed.is_none() {
            // A rebind may have committed before its response was saved. The
            // sealed rebind job recognizes that case with the original ID.
            let result = async {
                let current: RuntimeConfig = serde_json::from_value(
                    crate::communication_store::private_json(&job.owned.path(), 65536)
                        .map_err(|_| local("RUNTIME_CONFIG_NOT_PRIVATE"))?,
                )
                .map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
                job.owned.same_engine(&current)?;
                if serde_json::to_value(&current).ok()
                    == serde_json::to_value(&job.owned.config).ok()
                {
                    job.owned.stop().await?;
                    let client_name = job.source_binding["client_name"]
                        .as_str()
                        .ok_or_else(|| local("ORIGINAL_RECEIVER_BINDING_MISMATCH"))?;
                    let source = crate::communication_runtime::rebind_client(
                        &job.owned.config,
                        client_name,
                    )?;
                    if source.namespace != job.source_binding["namespace"]
                        || source.generation != job.source_binding["client_generation"].as_u64()
                    {
                        return Err(local("ORIGINAL_RECEIVER_BINDING_MISMATCH"));
                    }
                }
                let outcome =
                    crate::participant_rebind::rebind_host(&job.owned.path(), job.request.clone())
                        .await?;
                let committed: RuntimeConfig = serde_json::from_value(
                    crate::communication_store::private_json(&job.owned.path(), 65536)
                        .map_err(|_| local("RUNTIME_CONFIG_NOT_PRIVATE"))?,
                )
                .map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
                job.owned.same_engine(&committed)?;
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
        if let Err(error) = job.owned.restart(job.committed.as_ref().unwrap()).await {
            return Ok(
                json!({"state":"PENDING","operation_id":job.request.operation_id,"effect_certainty":"UNKNOWN","recovery":"RESUME_SAME_ATTACHMENT","blocker":{"stage":"RUNTIME_RESTART","code":error.code,"next_action":"RESUME_SAME_CODEX_ATTACHMENT"},"error":error,"existing_state_preserved":true}),
            );
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
            admin_endpoint: job.owned.config.state_directory.join("admin.json"),
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
        owner.close().await.unwrap();
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
        let engine_file = root.path().join("engine.json");
        write_private(&engine_file, &serde_json::to_vec(&engine).unwrap()).unwrap();
        codex_proxy_fixture(root.path());
        async fn run(executable: &Path, args: &[String], directory: &Path) -> Value {
            let output = tokio::process::Command::new(executable)
                .args(args)
                .env(
                    "PATH",
                    format!("{}:/usr/local/bin:/usr/bin:/bin", directory.display()),
                )
                .output()
                .await
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
            admin: local.join("runtime-worker/admin.json"),
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
        let mut initial = base.clone();
        initial.extend([
            "--engine-config".into(),
            engine_file.to_str().unwrap().into(),
            "--id".into(),
            "original-inbox".into(),
            "--send".into(),
            "--receive".into(),
            "--receive-mode".into(),
            "inbox".into(),
        ]);
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
            &local.join("runtime-worker/config.json"),
            65536,
        )
        .unwrap();
        let mut attach = base;
        attach.push("--codex".into());
        let choices = run(&executable, &attach, root.path()).await;
        assert_eq!(choices["blocker"]["code"], "CODEX_CHAT_SELECTION_REQUIRED");
        assert_eq!(choices["sessions"].as_array().unwrap().len(), 2);
        let original_launch =
            SecureStateStore::read_snapshot(&local.join("runtime-worker/bootstrap.state"), 65536)
                .unwrap()
                .to_vec();
        attach.extend(["--codex-chat".into(), "Worker".into()]);
        // An endpoint alone is not authority to stop an external runtime.
        {
            let mut registry = Connect::open(&local).unwrap();
            registry.registry.local_runtime_admins.remove("worker");
            registry.save().unwrap();
        }
        let denied = run(&executable, &attach, root.path()).await;
        assert_eq!(
            denied["error"]["code"], "LOCAL_RUNTIME_TAKEOVER_REQUIRED",
            "{denied}"
        );
        assert!(
            receiver.call(json!({"method":"binding"})).await.is_ok(),
            "unknown owner was stopped"
        );
        {
            let mut registry = Connect::open(&local).unwrap();
            registry
                .registry
                .local_runtime_admins
                .insert("worker".into(), local.join("runtime-worker/admin.json"));
            registry.save().unwrap();
        }
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
        assert_eq!(result["host_selection"]["thread_id"], "child");
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
            &local.join("runtime-worker/config.json"),
            65536,
        )
        .unwrap();
        assert_eq!(before_config["engines"], new_config["engines"]);
        assert_eq!(before_config["clients"], new_config["clients"]);
        let launch =
            SecureStateStore::read_snapshot(&local.join("runtime-worker/bootstrap.state"), 65536)
                .unwrap()
                .to_vec();
        assert_ne!(launch, original_launch);
        let repeated = run(&executable, &attach, root.path()).await;
        assert_eq!(repeated["state"], "LOCAL_CONFIGURED", "{repeated}");
        assert_eq!(
            SecureStateStore::read_snapshot(&local.join("runtime-worker/bootstrap.state"), 65536)
                .unwrap()
                .as_slice(),
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
            SecureStateStore::read_snapshot(&local.join("runtime-worker/bootstrap.state"), 65536)
                .unwrap()
                .as_slice(),
            launch.as_slice()
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let calls = std::fs::read_to_string(root.path().join("proxy-calls.jsonl")).unwrap();
                let inputs = calls
                    .lines()
                    .filter(|line| line.contains("turn/start") || line.contains("turn/steer"))
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
        restored.close().await.unwrap();
        assert_eq!(service.counts().await["journal_reads"], 0);
    }
}
