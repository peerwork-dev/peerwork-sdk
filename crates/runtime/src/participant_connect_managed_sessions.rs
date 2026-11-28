//! Owner-local launch policy and durable operations for independent Peers.
use super::*;
use crate::{onboarding_project::Directory, onboarding_store::Store};

const POLICY: &str = "session-launch.json";
const STATE: &str = "managed-sessions.state";
const STATE_LIMIT: usize = 1024 * 1024;

fn problem(code: &str) -> ParticipantError {
    ParticipantError::local(code, "SESSION_LIFECYCLE")
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionRequest {
    Start { operation_id: String, peer: String },
    Status { operation_id: String },
    Stop { operation_id: String },
}

fn tool(policy: &Policy) -> Value {
    let id = json!({"type":"string","description":"Stable launch operation ID."});
    json!({"name":"peerwork_session","description":"Start another enrolled local Peer as its authorized coordinator. Use the original launch ID for status, continuation and graceful stop. Dispatch after the selected session verifies receiving.",
        "inputSchema":{"type":"object","additionalProperties":false,"required":["request"],"properties":{"request":{"oneOf":[
          {"type":"object","additionalProperties":false,"required":["mode","operation_id","peer"],"properties":{"mode":{"const":"start"},"operation_id":id,"peer":{"type":"string","description":"Owner-configured local Peer handle.","enum":policy.peers.keys().collect::<Vec<_>>()}}},
          {"type":"object","additionalProperties":false,"required":["mode","operation_id"],"properties":{"mode":{"enum":["status","stop"]},"operation_id":id}}
        ]}}},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}})
}

impl SessionRequest {
    fn id(&self) -> &str {
        match self {
            Self::Start { operation_id, .. }
            | Self::Status { operation_id }
            | Self::Stop { operation_id } => operation_id,
        }
    }

    fn next_action(&self) -> Value {
        json!({"tool":"peerwork_session","arguments":{"request":self}})
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Harness {
    Codex,
    Opencode,
    Agy,
}

impl Harness {
    fn name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Opencode => "opencode",
            Self::Agy => "agy",
        }
    }

    fn target_id(self, adapter: &Value) -> Result<&str> {
        let (kind, field) = match self {
            Self::Codex => ("codex", "thread_id"),
            Self::Opencode => ("opencode", "session_id"),
            Self::Agy => ("agy-stdio", "conversation_id"),
        };
        adapter
            .get(field)
            .filter(|_| adapter["kind"] == kind)
            .and_then(Value::as_str)
            .ok_or_else(|| problem("SESSION_STATE_INVALID"))
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    harness: Harness,
    service_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executable: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_id: Option<String>,
}

impl Slot {
    fn valid(&self) -> bool {
        match self.harness {
            Harness::Codex => self.service_file.is_none()
                && self.executable.is_none() && self.conversation_id.is_none(),
            Harness::Opencode => self.service_file.as_ref().is_some_and(|file| file.is_absolute())
                && self.executable.is_none() && self.conversation_id.is_none(),
            Harness::Agy => self.service_file.is_none()
                && self.executable.as_ref().is_some_and(|file| file.is_absolute())
                && self.conversation_id.as_ref().is_some_and(|id| {
                    !id.is_empty() && id.len() <= 256
                        && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                }),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    format: String,
    controller: String,
    workspace_id: String,
    peers: BTreeMap<String, Slot>,
}

impl Policy {
    fn read(directory: &Directory) -> Result<Option<Self>> {
        let Some(wire) = directory.read(POLICY, 16 * 1024, true)? else {
            return Ok(None);
        };
        let policy: Self = decode(&wire)?;
        if policy.format != "peerwork.session-launch.v1"
            || !identifier(&policy.controller)
            || !token(&policy.workspace_id)
            || policy.peers.is_empty()
            || policy.peers.len() > 7
            || policy.peers.iter().any(|(peer, slot)| {
                !identifier(peer)
                    || peer == &policy.controller
                    || !slot.valid()
            })
        {
            return Err(problem("SESSION_LAUNCH_POLICY_INVALID"));
        }
        Ok(Some(policy))
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    peer: String,
    workspace: String,
    actor: String,
    origin: String,
    slot: Slot,
    project: Value,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Job {
    selection: Selection,
    source: WatchOptions,
    ownership: String,
    predecessor: Option<Value>,
    adapter: Option<Value>,
    probe_after: Option<u64>,
    stopping: bool,
    stopped: bool,
}

type Jobs = BTreeMap<String, Job>;

fn decode<T: serde::de::DeserializeOwned>(wire: &[u8]) -> Result<T> {
    peerwork_core::strict_json::parse_strict_json(wire)
        .ok()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or_else(|| problem("SESSION_CONFIGURATION_INVALID"))
}

fn jobs(store: &Store) -> Result<Jobs> {
    let Some(wire) = store.read_exact()? else {
        return Ok(Jobs::new());
    };
    if wire.len() > STATE_LIMIT {
        return Err(problem("SESSION_STATE_INVALID"));
    }
    decode(&wire)
}

fn save(store: &Store, jobs: &Jobs) -> Result<()> {
    let wire = serde_json::to_vec(jobs).map_err(|_| problem("SESSION_STATE_INVALID"))?;
    if wire.len() > STATE_LIMIT {
        return Err(problem("SESSION_HISTORY_LIMIT"));
    }
    store.write_exact(&wire)
}

fn outcome(id: &str, job: &Job, state: &str, code: &str) -> Value {
    let mut value = json!({"operation_id":id,"state":state,"code":code,"peer":job.selection.peer,
        "workspace_id":job.selection.workspace,"harness":job.selection.slot.harness,
        "session":job.adapter.as_ref().map(crate::communication_host::target_summary),
        "automatic_receiving":if state=="READY"{"VERIFIED"}else{"NOT_ATTESTED"},
        "model_response":"NOT_ATTESTED"});
    if state == "STOPPED" {
        value["stop_effect"] = json!(match job.selection.slot.harness {
            Harness::Codex => "DEDICATED_CODEX_HOST_EXITED",
            Harness::Opencode => "OPENCODE_RECEIVING_ROUTE_RETIRED",
            Harness::Agy => "AGY_RECEIVING_ROUTE_RETIRED",
        });
    }
    value
}

fn launch_pending(id: &str, job: &Job, code: &str) -> Value {
    let mut value = outcome(id, job, "STARTING", code);
    value["next_action"] = SessionRequest::Start {
        operation_id: id.into(),
        peer: job.selection.peer.clone(),
    }
    .next_action();
    value
}

fn stop_pending(id: &str, job: &Job, code: &str) -> Value {
    let mut value = outcome(id, job, "STOPPING", code);
    value["next_action"] = SessionRequest::Stop {
        operation_id: id.into(),
    }
    .next_action();
    value
}

fn on_original_source(job: &Job, watch: &WatchOptions) -> bool {
    let mut original = job.source.clone();
    original
        .host_destination
        .clone_from(&watch.host_destination);
    original == *watch
}

impl Connect {
    pub(crate) fn managed_session_tool(
        &self,
        caller: Option<&str>,
        workspace: Option<&str>,
    ) -> Option<Value> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let policy = Policy::read(&self.private_directory).ok().flatten()?;
        self.authorized_controller(&policy, caller, workspace)
            .ok()?;
        Some(tool(&policy))
    }

    fn authorized_controller(
        &self,
        policy: &Policy,
        caller: Option<&str>,
        workspace: Option<&str>,
    ) -> Result<()> {
        if caller != Some(policy.controller.as_str())
            || workspace != Some(policy.workspace_id.as_str())
        {
            return Err(problem("SESSION_CONTROLLER_NOT_AUTHORIZED"));
        }
        if self.profile_for_scope(caller, workspace)?.is_none() {
            return Err(problem("SESSION_CONTROLLER_SETUP_REQUIRED"));
        }
        Ok(())
    }

    fn managed_setup(&self, peer: &str, space: &str) -> Result<&Setup> {
        self.registry
            .active_by_scope
            .get(&format!("{peer}:{space}"))
            .and_then(|id| self.registry.setups.get(id))
            .filter(|setup| {
                setup.channel_receive
                    && setup
                        .profile
                        .as_ref()
                        .is_some_and(|p| p.receive_endpoint_path.is_some())
            })
            .ok_or_else(|| problem("SESSION_PEER_INBOX_REQUIRED"))
    }

    fn host_of(&self, setup: &Setup) -> Option<&Value> {
        setup
            .effective_host
            .as_ref()
            .and_then(|name| self.registry.hosts.get(name))
            .map(|host| &host.adapter)
    }
}

#[cfg(target_os = "linux")]
impl Connect {
    async fn managed_receiver(
        &self,
        selection: &Selection,
    ) -> Result<(RuntimeClient, Option<WatchOptions>)> {
        let profile = self
            .managed_setup(&selection.peer, &selection.workspace)?
            .profile
            .as_ref()
            .unwrap();
        if profile.expected_actor != selection.actor || profile.expected_origin != selection.origin
        {
            return Err(problem("SESSION_PEER_BINDING_CHANGED"));
        }
        let client = RuntimeClient::connect(
            profile.receive_endpoint_path.as_ref().unwrap().clone(),
            &selection.origin,
            &selection.actor,
        )
        .await?;
        let mut bindings: Vec<WatchOptions> =
            serde_json::from_value(client.call(json!({"method":"bindings"})).await?)
                .map_err(|_| problem("SESSION_PEER_BINDINGS_INVALID"))?;
        bindings.retain(|watch| {
            watch.workspace_id == selection.workspace
                && profile.scopes.values().any(|scope| {
                    scope.mailbox_id == watch.mailbox_id
                        && scope.membership_id == watch.membership_id
                })
        });
        if bindings.len() > 1 {
            return Err(problem("SESSION_PEER_SCOPE_REQUIRED"));
        }
        Ok((client, bindings.pop()))
    }

    async fn managed_delivery(&self, job: &Job, mode: &str) -> Result<Value> {
        let (receiver, watch) = self.managed_receiver(&job.selection).await?;
        let watch = watch.ok_or_else(|| problem("SESSION_PEER_SCOPE_REQUIRED"))?;
        let setup = self.managed_setup(&job.selection.peer, &job.selection.workspace)?;
        if !on_original_source(job, &watch)
            || watch.host_destination.is_none()
            || self.host_of(setup) != job.adapter.as_ref()
        {
            return Err(problem("SESSION_RECEIVING_TARGET_CHANGED"));
        }
        if mode != "status"
            && self
                .completed_host_binding(
                    &setup.desired,
                    setup,
                    &serde_json::to_value(&watch)
                        .map_err(|_| problem("SESSION_PEER_BINDINGS_INVALID"))?,
                )
                .await?
                .is_none()
        {
            return Err(problem("SESSION_RECEIVING_TARGET_CHANGED"));
        }
        receiver
            .call(json!({"method":"delivery","mode":mode,"options":watch}))
            .await
    }

    async fn managed_status(&self, id: &str, job: &Job) -> Result<Value> {
        if job.stopped {
            return Ok(outcome(id, job, "STOPPED", "SESSION_STOPPED"));
        }
        if job.stopping {
            return Ok(stop_pending(id, job, "REPEAT_MANAGED_SESSION_STOP"));
        }
        let Some(after) = job.probe_after else {
            return Ok(launch_pending(id, job, "REPEAT_MANAGED_SESSION_START"));
        };
        let delivery = match self.managed_delivery(job, "status").await {
            Ok(value) => value,
            Err(error) => return Ok(outcome(id, job, "RECOVERING", &error.code)),
        };
        let expected = job
            .adapter
            .as_ref()
            .map(crate::communication_host::target_summary);
        let ready = delivery["observations"].as_array().is_some_and(|observed| {
            observed.len() == 1 && {
                let value = &observed[0];
                expected.as_ref() == value.get("target")
                    && value["current_delivery"]["state"] == "READY"
                    && value["receiver"]["receiver_link_verified"] == true
                    && value["notification"]["automatic_receiving"] == "VERIFIED"
                    && value["notification"]["last_verified_at"]
                        .as_u64()
                        .is_some_and(|at| at >= after)
            }
        });
        if !ready
            && job.selection.slot.harness == Harness::Codex
            && !crate::participant_session_codex::running(&self.session_directory(id))
                .map_err(problem)?
        {
            return Ok(launch_pending(
                id,
                job,
                "CODEX_MANAGED_HOST_RESTART_REQUIRED",
            ));
        }
        let mut result = outcome(
            id,
            job,
            if ready { "READY" } else { "STARTING" },
            if ready {
                "SESSION_RECEIVING_VERIFIED"
            } else {
                "SESSION_RECEIVING_UNVERIFIED"
            },
        );
        if !ready {
            result["next_action"] = SessionRequest::Status {
                operation_id: id.into(),
            }
            .next_action();
            result["retry_after_ms"] = json!(1000);
        }
        result["delivery"] = delivery["observations"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(|value| value["current_delivery"].clone())
            .unwrap_or(Value::Null);
        Ok(result)
    }

    async fn start_managed(
        &mut self,
        policy: &Policy,
        store: &Store,
        records: &mut Jobs,
        id: &str,
        peer: &str,
    ) -> Result<Value> {
        let slot = policy
            .peers
            .get(peer)
            .filter(|_| identifier(peer))
            .ok_or_else(|| problem("SESSION_PEER_NOT_AUTHORIZED"))?
            .clone();
        let registration = self
            .registry
            .participants
            .get(peer)
            .ok_or_else(|| problem("SESSION_PEER_NOT_ENROLLED"))?;
        let controller = &self.registry.participants[&policy.controller];
        if registration.actor_id == controller.actor_id || registration.origin != controller.origin
        {
            return Err(problem("SESSION_INDEPENDENT_PEER_REQUIRED"));
        }
        let workspace = &policy.workspace_id;
        let (project, name, entry) =
            install::session_installation(self, peer, workspace, slot.harness.name())?;
        let project_identity = Directory::open(&project)?.identity()?;
        let selection = Selection {
            peer: peer.into(),
            workspace: workspace.clone(),
            actor: registration.actor_id.clone(),
            origin: registration.origin.clone(),
            slot,
            project: project_identity,
        };
        let mut job = match records.get(id) {
            Some(job) if job.selection == selection => job.clone(),
            Some(_) => return Err(problem("SESSION_OPERATION_ID_CONFLICT")),
            None => {
                if records.len() >= 1024 {
                    return Err(problem("SESSION_HISTORY_LIMIT"));
                }
                if let Some((original_id, original)) = records.iter().find(|(_, job)| {
                    !job.stopped
                        && job.selection.actor == selection.actor
                        && job.selection.workspace == *workspace
                }) {
                    let mut error = problem("SESSION_PEER_ALREADY_MANAGED");
                    if policy.peers.contains_key(&original.selection.peer) {
                        error.details = Some(json!({"original_launch_id":original_id,
                            "next_action":SessionRequest::Status { operation_id: original_id.clone() }.next_action()}));
                    }
                    return Err(error);
                }
                let (_, watch) = self.managed_receiver(&selection).await?;
                let watch = watch.ok_or_else(|| problem("SESSION_PEER_SCOPE_REQUIRED"))?;
                let previous = self.host_of(self.managed_setup(peer, workspace)?).cloned();
                if watch.host_destination.is_some() || previous.is_some() {
                    let owned_stopped = previous.as_ref().is_some_and(|adapter| {
                        records.values().any(|job| {
                            job.stopped
                                && job.selection == selection
                                && job.adapter.as_ref() == Some(adapter)
                        })
                    });
                    if !owned_stopped {
                        let mut error = problem("SESSION_PEER_HAS_EXISTING_RECEIVER");
                        error.recovery = "CHECK_EXISTING_PEER_RECEIVING".into();
                        error.details = Some(json!({"next_action":{"tool":"peerwork_reachability",
                            "arguments":{"workspace":workspace,"actor":selection.actor}}}));
                        return Err(error);
                    }
                }
                let job = Job {
                    selection,
                    source: watch,
                    ownership: crate::communication_host::random_token().map_err(problem)?,
                    predecessor: previous,
                    adapter: None,
                    probe_after: None,
                    stopping: false,
                    stopped: false,
                };
                records.insert(id.into(), job.clone());
                save(store, records)?;
                job
            }
        };
        if job.stopping {
            return self.managed_status(id, &job).await;
        }
        if job.probe_after.is_some()
            && (job.selection.slot.harness != Harness::Codex
                || crate::participant_session_codex::running(&self.session_directory(id))
                    .map_err(problem)?)
        {
            return self.managed_status(id, &job).await;
        }
        let key = format!("{peer}:{workspace}");
        let (_, original_watch) = self.managed_receiver(&job.selection).await?;
        if original_watch
            .as_ref()
            .is_some_and(|watch| !on_original_source(&job, watch))
        {
            return Err(problem("SESSION_PEER_BINDING_CHANGED"));
        }
        let exact_attachment = job
            .adapter
            .as_ref()
            .is_some_and(|adapter| self.codex_attachment_targets(&key, adapter));
        let attachment_pending = self.codex_attachment_pending(peer, workspace);
        let phase_host = self.host_of(self.managed_setup(peer, workspace)?);
        if phase_host != job.predecessor.as_ref() && phase_host != job.adapter.as_ref()
            || attachment_pending && !exact_attachment
        {
            return Err(problem("SESSION_RECEIVING_TARGET_CHANGED"));
        }
        // Resident rebind temporarily disables the watch. Only its exact
        // persisted attachment may continue through that intermediate state.
        if original_watch.is_none() && !(attachment_pending && exact_attachment) {
            return Err(problem("SESSION_PEER_SCOPE_REQUIRED"));
        }
        let admin = self.runtime_admin(peer, None).await?;
        let status = crate::communication_runtime::call(&admin, json!({"method":"status"})).await?;
        let features = status["value"]["optional_features"].as_array();
        let required = match job.selection.slot.harness {
            Harness::Agy => "agy-acp-resident-rebind-v1",
            _ => "resident-scope-rebind-v1",
        };
        if !features.is_some_and(|features| features.iter().any(|feature| feature == required)) {
            return Err(problem("SESSION_RESIDENT_RUNTIME_REQUIRED"));
        }
        let directory = self.session_directory(id);
        let adapter = match job.selection.slot.harness {
            Harness::Codex => {
                if job.adapter.is_some()
                    && !crate::participant_session_codex::running(&directory).map_err(problem)?
                {
                    job.probe_after = None;
                    records.insert(id.into(), job.clone());
                    save(store, records)?;
                }
                crate::participant_session_codex::launch(
                    &directory,
                    &project,
                    &name,
                    &entry,
                    job.adapter.as_ref(),
                )
                .await
            }
            Harness::Opencode => {
                use crate::participant_session_opencode as host;
                let file = job.selection.slot.service_file.as_ref().unwrap();
                match host::verify_setup(file.clone(), project.clone(), name, entry).await {
                    Ok(()) => (),
                    Err("OPENCODE_MANAGED_MCP_NOT_READY") => {
                        return Ok(launch_pending(id, &job, "OPENCODE_MANAGED_MCP_NOT_READY"));
                    }
                    Err(code) => return Err(problem(code)),
                }
                let session = match &job.adapter {
                    Some(adapter) => {
                        let session = job.selection.slot.harness.target_id(adapter)?;
                        host::validate(
                            file.clone(),
                            project.clone(),
                            job.ownership.clone(),
                            session.into(),
                        )
                        .await
                        .map_err(problem)?;
                        session.to_owned()
                    }
                    None => {
                        host::launch(file.clone(), project.clone(), job.ownership.clone(), true)
                            .await
                            .map_err(problem)?
                    }
                };
                Ok(host::adapter(file, &project, &session))
            }
            Harness::Agy => Ok(json!({
                "kind": "agy-stdio", "managed": true, "stdio_protocol": "acp",
                "executable": job.selection.slot.executable,
                "working_directory": project,
                "conversation_id": job.selection.slot.conversation_id,
                "mcp_server": name,
                "acp_client": {"registry": self.directory, "participant": peer, "workspace": workspace},
            })),
        }
        .map_err(problem)?;
        if job.adapter.as_ref().is_some_and(|saved| saved != &adapter) {
            return Err(problem("SESSION_LAUNCH_TARGET_CHANGED"));
        }
        if job.adapter.is_none() {
            job.adapter = Some(adapter.clone());
            records.insert(id.into(), job.clone());
            save(store, records)?;
        }
        let setup = self.managed_setup(peer, workspace)?;
        let attached = match original_watch.filter(|watch| watch.host_destination.is_some()) {
            Some(watch) if self.host_of(setup) == Some(&adapter) => self
                .completed_host_binding(
                    &setup.desired,
                    setup,
                    &serde_json::to_value(watch)
                        .map_err(|_| problem("SESSION_PEER_BINDINGS_INVALID"))?,
                )
                .await?
                .is_some(),
            _ => false,
        };
        if !attached {
            let setup = self.managed_setup(peer, workspace)?;
            let desired = if self.codex_attachment_targets(&key, &adapter) {
                self.codex_original_invocation(peer, workspace)
                    .ok_or_else(|| problem("SESSION_STATE_INVALID"))?
            } else {
                setup.desired.clone()
            };
            let target = job.selection.slot.harness.target_id(&adapter)?;
            let attached = self
                .attach_selected_host(
                    desired,
                    adapter.clone(),
                    target,
                    Some(RuntimeSelection {
                        admin_endpoint: admin,
                        config_path: None,
                    }),
                )
                .await?;
            let (_, watched) = self.managed_receiver(&job.selection).await?;
            if watched
                .as_ref()
                .is_some_and(|watch| !on_original_source(&job, watch))
            {
                return Err(problem("SESSION_PEER_BINDING_CHANGED"));
            }
            if self.host_of(self.managed_setup(peer, workspace)?) != Some(&adapter)
                || watched.is_none_or(|watch| watch.host_destination.is_none())
            {
                let mut result = launch_pending(id, &job, "SESSION_ATTACHMENT_PENDING");
                result["blocker"] = attached["blocker"].clone();
                return Ok(result);
            }
        }
        if job.probe_after.is_none() {
            let requested_at = stamp();
            self.managed_delivery(&job, "resume").await?;
            job.probe_after = Some(requested_at);
            records.insert(id.into(), job.clone());
            save(store, records)?;
        }
        self.managed_status(id, &job).await
    }

    async fn stop_managed(
        &self,
        store: &Store,
        records: &mut Jobs,
        id: &str,
        mut job: Job,
    ) -> Result<Value> {
        if job.stopped {
            return Ok(outcome(id, &job, "STOPPED", "SESSION_STOPPED"));
        }
        let directory = self.session_directory(id);
        if job.adapter.is_none() {
            // Resume the original start to reconcile any partial host creation
            // before attempting a stop. No unproven host is interrupted.
            return Ok(launch_pending(
                id,
                &job,
                "RECONCILE_SESSION_TARGET_BEFORE_STOP",
            ));
        }
        if !job.stopping {
            job.stopping = true;
            records.insert(id.into(), job.clone());
            save(store, records)?;
        }
        let adapter = job.adapter.as_ref().unwrap();
        let current =
            self.host_of(self.managed_setup(&job.selection.peer, &job.selection.workspace)?);
        if current == Some(adapter) {
            let pause = self.managed_delivery(&job, "pause").await?;
            if pause["state"] != "PAUSED"
                || pause["destinations"].as_array().is_none_or(|rows| {
                    rows.len() != 1 || rows[0]["already_inflight"].as_u64() != Some(0)
                })
            {
                return Ok(stop_pending(id, &job, "SESSION_DELIVERY_PAUSE_PENDING"));
            }
        } else if current != job.predecessor.as_ref() {
            return Err(problem("SESSION_RECEIVING_TARGET_CHANGED"));
        }
        let stopped = match job.selection.slot.harness {
            Harness::Codex => crate::participant_session_codex::stop(&directory, Some(adapter))
                .await
                .map_err(problem)?,
            Harness::Opencode => {
                use crate::participant_session_opencode as host;
                let file = job.selection.slot.service_file.as_ref().unwrap();
                let project = PathBuf::from(
                    adapter["directory"]
                        .as_str()
                        .ok_or_else(|| problem("SESSION_STATE_INVALID"))?,
                );
                let id = job.selection.slot.harness.target_id(adapter)?;
                // An idle read cannot fence input from other clients of the
                // shared OpenCode service. Retire only Peerwork's route.
                host::idle(file.clone(), project, job.ownership.clone(), id.into())
                    .await
                    .map_err(problem)?
            }
            Harness::Agy => {
                let observations = self.managed_delivery(&job, "status").await?;
                observations["observations"].as_array().is_some_and(|rows| {
                    rows.len() == 1 && rows[0]["transport_health"]["execution_state"] == "IDLE"
                })
            }
        };
        if stopped {
            job.stopped = true;
            records.insert(id.into(), job.clone());
            save(store, records)?;
        }
        if stopped {
            Ok(outcome(id, &job, "STOPPED", "SESSION_STOPPED"))
        } else {
            Ok(stop_pending(id, &job, "SESSION_WAITING_FOR_IDLE_OR_EXIT"))
        }
    }

    fn session_directory(&self, id: &str) -> PathBuf {
        self.directory
            .join(format!("s-{}", &sha256_hex(id.as_bytes())[..20]))
    }

    pub(crate) async fn managed_session(
        &mut self,
        caller: Option<&str>,
        workspace: Option<&str>,
        request: SessionRequest,
    ) -> Result<Value> {
        let policy = Policy::read(&self.private_directory)?
            .ok_or_else(|| problem("SESSION_LAUNCH_POLICY_REQUIRED"))?;
        self.authorized_controller(&policy, caller, workspace)?;
        let id = request.id();
        if !identifier(id) {
            return Err(problem("SESSION_OPERATION_ID_INVALID"));
        }
        let store = Store::anchored(self.private_directory.clone(), STATE, true)?;
        let mut records = jobs(&store)?;
        if let Some(job) = records.get(id) {
            if job.selection.workspace != policy.workspace_id
                || !policy.peers.contains_key(&job.selection.peer)
            {
                return Err(problem("SESSION_PEER_NOT_AUTHORIZED"));
            }
            if !matches!(request, SessionRequest::Start { .. }) {
                let job = job.clone();
                return match request {
                    SessionRequest::Status { .. } => self.managed_status(id, &job).await,
                    SessionRequest::Stop { .. } => self
                        .stop_managed(&store, &mut records, id, job)
                        .await
                        .map_err(|error| {
                            recovery_problem(error, &request, "REPEAT_MANAGED_SESSION_STOP")
                        }),
                    SessionRequest::Start { .. } => unreachable!(),
                };
            }
        }
        match &request {
            SessionRequest::Start { peer, .. } => {
                let result = self
                    .start_managed(&policy, &store, &mut records, id, peer)
                    .await;
                if records
                    .get(id)
                    .is_some_and(|job| &job.selection.peer == peer)
                {
                    result.map_err(|error| {
                        if error.code == "SESSION_OPERATION_ID_CONFLICT" {
                            error
                        } else {
                            recovery_problem(error, &request, "REPEAT_MANAGED_SESSION_START")
                        }
                    })
                } else {
                    result
                }
            }
            _ => Err(problem("SESSION_OPERATION_NOT_FOUND")),
        }
    }
}

fn recovery_problem(
    mut error: ParticipantError,
    request: &SessionRequest,
    next: &str,
) -> ParticipantError {
    error.effect_certainty = "UNKNOWN".into();
    error.recovery = next.into();
    let mut details = error.details.take().unwrap_or_else(|| json!({}));
    if !details.is_object() {
        details = json!({"cause":details});
    }
    details["next_action"] = request.next_action();
    error.details = Some(details);
    error.original(request.id())
}

#[cfg(not(target_os = "linux"))]
impl Connect {
    pub(crate) async fn managed_session(
        &mut self,
        _: Option<&str>,
        _: Option<&str>,
        _: SessionRequest,
    ) -> Result<Value> {
        Err(problem("SESSION_LAUNCH_PLATFORM_UNSUPPORTED"))
    }
}

pub fn cli(args: &[String]) -> Value {
    if args == ["--help"] {
        return json!({"usage":"peerwork session --local REGISTRY start --id ID --peer HANDLE | peerwork session --local REGISTRY status|stop --id ID"});
    }
    let result = (|| -> Result<Value> {
        let [local, registry, mode, id_flag, id, rest @ ..] = args else {
            return Err(problem("SESSION_ARGUMENT_INVALID"));
        };
        if local != "--local" || id_flag != "--id" {
            return Err(problem("SESSION_ARGUMENT_INVALID"));
        }
        let request = match (mode.as_str(), rest) {
            ("start", [flag, peer]) if flag == "--peer" => SessionRequest::Start {
                operation_id: id.clone(),
                peer: peer.clone(),
            },
            ("status", []) => SessionRequest::Status {
                operation_id: id.clone(),
            },
            ("stop", []) => SessionRequest::Stop {
                operation_id: id.clone(),
            },
            _ => return Err(problem("SESSION_ARGUMENT_INVALID")),
        };
        let registry =
            std::path::absolute(registry).map_err(|_| problem("SESSION_ARGUMENT_INVALID"))?;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| problem("EXECUTOR_FAILED"))?;
        executor.block_on(async {
            let mut connect = Connect::open(&registry)?;
            let policy = Policy::read(&connect.private_directory)?
                .ok_or_else(|| problem("SESSION_LAUNCH_POLICY_REQUIRED"))?;
            connect
                .managed_session(
                    Some(&policy.controller),
                    Some(&policy.workspace_id),
                    request,
                )
                .await
        })
    })();
    result.unwrap_or_else(|error| json!({"ok":false,"state":"FAILED","error":error}))
}

#[cfg(all(test, target_os = "linux"))]
#[path = "participant_managed_session_http_tests.rs"]
mod tests;
