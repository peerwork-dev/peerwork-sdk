//! Owner-local launch policy and durable operations for independent Peers.
use super::*;
use crate::{onboarding_project::Directory, onboarding_store::Store};

const POLICY: &str = "session-launch.json";
const STATE: &str = "managed-sessions.state";
const STATE_LIMIT: usize = 1024 * 1024;

fn problem(code: &str) -> ParticipantError {
    ParticipantError::local(code, "SESSION_LIFECYCLE")
}

#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionRequest {
    Start { operation_id: String, peer: String },
    Status { operation_id: String },
    Stop { operation_id: String },
}

pub(crate) fn tool() -> Value {
    let id = json!({"type":"string","description":"Stable launch operation ID."});
    json!({"name":"peerwork_session","description":"Manage a preauthorized local Peer session. Reuse the same launch ID for status, recovery and a graceful stop. Peer receiving must verify before dispatch.",
        "inputSchema":{"type":"object","additionalProperties":false,"required":["request"],"properties":{"request":{"oneOf":[
          {"type":"object","additionalProperties":false,"required":["mode","operation_id","peer"],"properties":{"mode":{"const":"start"},"operation_id":id,"peer":{"type":"string","description":"Owner-configured local Peer handle."}}},
          {"type":"object","additionalProperties":false,"required":["mode","operation_id"],"properties":{"mode":{"enum":["status","stop"]},"operation_id":id}}
        ]}}},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}})
}

impl SessionRequest {
    fn id(&self) -> &str {
        match self {
            Self::Start { operation_id, .. } |
            Self::Status { operation_id } |
            Self::Stop { operation_id } => operation_id,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Harness { Codex, Opencode }

impl Harness {
    fn name(self) -> &'static str {
        match self { Self::Codex => "codex", Self::Opencode => "opencode" }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    harness: Harness,
    service_file: Option<PathBuf>,
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
        let Some(wire) = directory.read(POLICY, 16 * 1024, true)? else { return Ok(None); };
        let policy: Self = decode(&wire)?;
        if policy.format != "peerwork.session-launch.v1" || !identifier(&policy.controller)
            || !token(&policy.workspace_id) || policy.peers.is_empty() || policy.peers.len() > 7
            || policy.peers.iter().any(|(peer, slot)| {
                !identifier(peer) || peer == &policy.controller || match slot.harness {
                    Harness::Codex => slot.service_file.is_some(),
                    Harness::Opencode => slot.service_file.as_ref().is_none_or(|p| !p.is_absolute()),
                }
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
    ownership: String,
    predecessor: Option<Value>,
    adapter: Option<Value>,
    probe_after: Option<u64>,
    stopping: bool,
    stopped: bool,
}

type Jobs = BTreeMap<String, Job>;

fn decode<T: serde::de::DeserializeOwned>(wire: &[u8]) -> Result<T> {
    peerwork_core::strict_json::parse_strict_json(wire).ok()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or_else(|| problem("SESSION_CONFIGURATION_INVALID"))
}

fn jobs(store: &Store) -> Result<Jobs> {
    let Some(wire) = store.read_exact()? else { return Ok(Jobs::new()); };
    if wire.len() > STATE_LIMIT { return Err(problem("SESSION_STATE_INVALID")); }
    decode(&wire)
}

fn save(store: &Store, jobs: &Jobs) -> Result<()> {
    let wire = serde_json::to_vec(jobs).map_err(|_| problem("SESSION_STATE_INVALID"))?;
    if wire.len() > STATE_LIMIT { return Err(problem("SESSION_HISTORY_LIMIT")); }
    store.write_exact(&wire)
}

fn outcome(id: &str, job: &Job, state: &str, code: &str) -> Value {
    json!({"operation_id":id,"state":state,"code":code,"peer":job.selection.peer,
        "workspace_id":job.selection.workspace,"harness":job.selection.slot.harness,
        "session":job.adapter.as_ref().map(crate::communication_host::target_summary),
        "automatic_receiving":if state=="READY"{"VERIFIED"}else{"NOT_ATTESTED"},
        "model_response":"NOT_ATTESTED"})
}

impl Connect {
    pub(crate) fn managed_sessions_available(&self, caller: Option<&str>, workspace: Option<&str>) -> bool {
        cfg!(target_os = "linux") && Policy::read(&self.private_directory).ok().flatten()
            .is_some_and(|policy| self.authorized_controller(&policy, caller, workspace).is_ok())
    }

    fn authorized_controller(&self, policy: &Policy, caller: Option<&str>, workspace: Option<&str>) -> Result<()> {
        if caller != Some(policy.controller.as_str()) || workspace != Some(policy.workspace_id.as_str()) {
            return Err(problem("SESSION_CONTROLLER_NOT_AUTHORIZED"));
        }
        if self.profile_for_scope(caller, workspace)?.is_none() {
            return Err(problem("SESSION_CONTROLLER_SETUP_REQUIRED"));
        }
        Ok(())
    }

    fn managed_setup(&self, peer: &str, space: &str) -> Result<&Setup> {
        self.registry.active_by_scope.get(&format!("{peer}:{space}"))
            .and_then(|id| self.registry.setups.get(id))
            .filter(|setup| setup.channel_receive
                && setup.profile.as_ref().is_some_and(|p| p.receive_endpoint_path.is_some()))
            .ok_or_else(|| problem("SESSION_PEER_INBOX_REQUIRED"))
    }

    fn host_of(&self, setup: &Setup) -> Option<&Value> {
        setup.effective_host.as_ref().and_then(|name| self.registry.hosts.get(name)).map(|host| &host.adapter)
    }
}

#[cfg(target_os = "linux")]
impl Connect {
    async fn managed_receiver(&self, selection: &Selection) -> Result<(RuntimeClient, WatchOptions)> {
        let profile = self.managed_setup(&selection.peer, &selection.workspace)?.profile.as_ref().unwrap();
        if profile.expected_actor != selection.actor || profile.expected_origin != selection.origin {
            return Err(problem("SESSION_PEER_BINDING_CHANGED"));
        }
        let client = RuntimeClient::connect(
            profile.receive_endpoint_path.as_ref().unwrap().clone(),
            &selection.origin, &selection.actor,
        ).await?;
        let mut bindings: Vec<WatchOptions> = serde_json::from_value(client.call(json!({"method":"bindings"})).await?)
            .map_err(|_| problem("SESSION_PEER_BINDINGS_INVALID"))?;
        bindings.retain(|watch| watch.workspace_id == selection.workspace
            && profile.scopes.values().any(|scope| scope.mailbox_id == watch.mailbox_id
                && scope.membership_id == watch.membership_id));
        if bindings.len() != 1 { return Err(problem("SESSION_PEER_SCOPE_REQUIRED")); }
        Ok((client, bindings.pop().unwrap()))
    }

    async fn managed_delivery(&self, job: &Job, mode: &str) -> Result<Value> {
        let (receiver, watch) = self.managed_receiver(&job.selection).await?;
        let setup = self.managed_setup(&job.selection.peer, &job.selection.workspace)?;
        if watch.host_destination.is_none() || self.host_of(setup) != job.adapter.as_ref() {
            return Err(problem("SESSION_RECEIVING_TARGET_CHANGED"));
        }
        receiver.call(json!({"method":"delivery","mode":mode,"options":watch})).await
    }

    async fn managed_status(&self, id: &str, job: &Job) -> Result<Value> {
        if job.stopped { return Ok(outcome(id, job, "STOPPED", "SESSION_STOPPED")); }
        if job.stopping { return Ok(outcome(id, job, "STOPPING", "REPEAT_MANAGED_SESSION_STOP")); }
        let Some(after) = job.probe_after else { return Ok(outcome(id, job, "STARTING", "REPEAT_MANAGED_SESSION_START")); };
        let delivery = match self.managed_delivery(job, "status").await {
            Ok(value) => value,
            Err(error) => return Ok(outcome(id, job, "RECOVERING", &error.code)),
        };
        let ready = delivery["observations"].as_array().is_some_and(|observed| observed.len() == 1 && {
            let value = &observed[0];
            value["current_delivery"]["state"] == "READY"
                && value["receiver"]["receiver_link_verified"] == true
                && value["notification"]["automatic_receiving"] == "VERIFIED"
                && value["notification"]["last_verified_at"].as_u64().is_some_and(|at| at >= after)
        });
        let mut result = outcome(id, job, if ready {"READY"}else{"STARTING"},
            if ready {"SESSION_RECEIVING_VERIFIED"} else {"SESSION_RECEIVING_UNVERIFIED"});
        result["delivery"] = delivery["observations"].as_array().and_then(|rows|rows.first())
            .map(|value| value["current_delivery"].clone()).unwrap_or(Value::Null);
        Ok(result)
    }

    async fn start_managed(
        &mut self, policy: &Policy, store: &Store, records: &mut Jobs, id: &str, peer: &str,
    ) -> Result<Value> {
        let slot = policy.peers.get(peer).filter(|_| identifier(peer))
            .ok_or_else(|| problem("SESSION_PEER_NOT_AUTHORIZED"))?.clone();
        let registration = self.registry.participants.get(peer).ok_or_else(|| problem("SESSION_PEER_NOT_ENROLLED"))?;
        let controller = &self.registry.participants[&policy.controller];
        if registration.actor_id == controller.actor_id || registration.origin != controller.origin {
            return Err(problem("SESSION_INDEPENDENT_PEER_REQUIRED"));
        }
        let workspace = &policy.workspace_id;
        let (project, name, entry) = install::session_installation(self, peer, workspace, slot.harness.name())?;
        let project_identity = Directory::open(&project)?.identity()?;
        let selection = Selection { peer:peer.into(), workspace:workspace.clone(), actor:registration.actor_id.clone(),
            origin:registration.origin.clone(), slot, project:project_identity };
        let mut job = match records.get(id) {
            Some(job) if job.selection == selection => job.clone(),
            Some(_) => return Err(problem("SESSION_OPERATION_ID_CONFLICT")),
            None => {
                if records.len() >= 1024 { return Err(problem("SESSION_HISTORY_LIMIT")); }
                if records.values().any(|job| !job.stopped && job.selection.actor == selection.actor
                    && job.selection.workspace == *workspace) {
                    return Err(problem("SESSION_PEER_ALREADY_MANAGED"));
                }
                let (_, watch) = self.managed_receiver(&selection).await?;
                let previous = self.host_of(self.managed_setup(peer, workspace)?).cloned();
                if watch.host_destination.is_some() || previous.is_some() {
                    let owned_stopped = previous.as_ref().is_some_and(|adapter| records.values().any(|job|
                        job.stopped && job.selection == selection && job.adapter.as_ref() == Some(adapter)));
                    if !owned_stopped { return Err(problem("SESSION_PEER_HAS_EXISTING_HOST_USE_HANDOFF")); }
                }
                let job = Job {selection, ownership:crate::communication_host::random_token().map_err(problem)?,
                    predecessor:previous, adapter:None, probe_after:None, stopping:false, stopped:false};
                records.insert(id.into(), job.clone());
                save(store, records)?;
                job
            }
        };
        if job.stopping { return self.managed_status(id, &job).await; }
        if job.probe_after.is_some() {
            let current = self.managed_status(id, &job).await?;
            if current["state"] == "READY" { return Ok(current); }
        }
        let key = format!("{peer}:{workspace}");
        let phase_host = self.host_of(self.managed_setup(peer, workspace)?);
        if phase_host != job.predecessor.as_ref() && phase_host != job.adapter.as_ref()
            || self.codex_attachment_pending(peer, workspace)
                && job.adapter.as_ref().is_none_or(|adapter| !self.codex_attachment_targets(&key, adapter))
        {
            return Err(problem("SESSION_RECEIVING_TARGET_CHANGED"));
        }
        let admin = self.runtime_admin(peer, None).await?;
        let status = crate::communication_runtime::call(&admin, json!({"method":"status"})).await?;
        if !status["value"]["optional_features"].as_array().is_some_and(|features|
            features.iter().any(|feature| feature == "resident-scope-rebind-v1")) {
            return Err(problem("SESSION_RESIDENT_RUNTIME_REQUIRED"));
        }
        let directory = self.session_directory(id);
        let adapter = match job.selection.slot.harness {
            Harness::Codex => {
                if job.adapter.is_some() && !crate::participant_session_codex::running(&directory).map_err(problem)? {
                    job.probe_after = None;
                    records.insert(id.into(), job.clone());
                    save(store, records)?;
                }
                crate::participant_session_codex::launch(&directory, &project, &name, &entry, job.adapter.as_ref()).await
            }
            Harness::Opencode => {
                use crate::participant_session_opencode as host;
                let file = job.selection.slot.service_file.as_ref().unwrap();
                host::verify_setup(file.clone(), project.clone(), name, entry).await.map_err(problem)?;
                let session = match &job.adapter {
                    Some(adapter) => {
                        let session = adapter["session_id"].as_str().ok_or_else(|| problem("SESSION_STATE_INVALID"))?;
                        host::validate(file.clone(), project.clone(), job.ownership.clone(), session.into()).await.map_err(problem)?;
                        session.to_owned()
                    }
                    None => host::launch(file.clone(), project.clone(), job.ownership.clone(), true).await.map_err(problem)?,
                };
                Ok(host::adapter(file, &project, &session))
            }
        }.map_err(problem)?;
        if job.adapter.as_ref().is_some_and(|saved| saved != &adapter) {
            return Err(problem("SESSION_LAUNCH_TARGET_CHANGED"));
        }
        if job.adapter.is_none() {
            job.adapter = Some(adapter.clone());
            records.insert(id.into(), job.clone());
            save(store, records)?;
        }
        let attached = self.host_of(self.managed_setup(peer, workspace)?) == Some(&adapter);
        if !attached {
            let setup = self.managed_setup(peer, workspace)?;
            let desired = if self.codex_attachment_targets(&key, &adapter) {
                self.codex_original_invocation(peer, workspace).ok_or_else(|| problem("SESSION_STATE_INVALID"))?
            } else {
                setup.desired.clone()
            };
            let target = adapter["thread_id"].as_str().or_else(|| adapter["session_id"].as_str())
                .ok_or_else(|| problem("SESSION_STATE_INVALID"))?.to_owned();
            let attached = self.attach_selected_host(desired, adapter.clone(), &target,
                Some(RuntimeSelection { admin_endpoint:admin, config_path:None })).await?;
            if self.host_of(self.managed_setup(peer, workspace)?) != Some(&adapter) {
                let mut result = outcome(id, &job, "STARTING", "SESSION_ATTACHMENT_PENDING");
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

    async fn stop_managed(&self, store: &Store, records: &mut Jobs, id: &str, mut job: Job) -> Result<Value> {
        if job.stopped { return Ok(outcome(id, &job, "STOPPED", "SESSION_STOPPED")); }
        let directory = self.session_directory(id);
        if job.adapter.is_none() {
            // Resume the original start to reconcile any partial host creation
            // before attempting a stop. No unproven host is interrupted.
            return Ok(outcome(id, &job, "STARTING", "RECONCILE_SESSION_TARGET_BEFORE_STOP"));
        }
        if !job.stopping {
            job.stopping = true;
            records.insert(id.into(), job.clone());
            save(store, records)?;
        }
        let adapter = job.adapter.as_ref().unwrap();
        let current = self.host_of(self.managed_setup(&job.selection.peer, &job.selection.workspace)?);
        if current == Some(adapter) {
            let pause = self.managed_delivery(&job, "pause").await?;
            if pause["state"] != "PAUSED" || pause["destinations"].as_array().is_none_or(|rows|
                rows.len() != 1 || rows[0]["already_inflight"].as_u64() != Some(0)) {
                return Ok(outcome(id, &job, "STOPPING", "SESSION_DELIVERY_PAUSE_PENDING"));
            }
        } else if current != job.predecessor.as_ref() {
            return Err(problem("SESSION_RECEIVING_TARGET_CHANGED"));
        }
        let stopped = match job.selection.slot.harness {
            Harness::Codex => crate::participant_session_codex::stop(&directory, Some(adapter)).await.map_err(problem)?,
            Harness::Opencode => {
                use crate::participant_session_opencode as host;
                let file = job.selection.slot.service_file.as_ref().unwrap();
                let project = PathBuf::from(adapter["directory"].as_str().ok_or_else(|| problem("SESSION_STATE_INVALID"))?);
                let id = adapter["session_id"].as_str().ok_or_else(|| problem("SESSION_STATE_INVALID"))?;
                if host::idle(file.clone(), project.clone(), job.ownership.clone(), id.into()).await.map_err(problem)? {
                    host::stop(file.clone(), project, job.ownership.clone(), id.into()).await.map_err(problem)?;
                    true
                } else { false }
            }
        };
        if stopped {
            job.stopped = true;
            records.insert(id.into(), job.clone());
            save(store, records)?;
        }
        Ok(outcome(id, &job, if stopped {"STOPPED"} else {"STOPPING"},
            if stopped {"SESSION_STOPPED"} else {"SESSION_WAITING_FOR_IDLE_OR_EXIT"}))
    }

    fn session_directory(&self, id: &str) -> PathBuf {
        self.directory.join(format!("s-{}", &sha256_hex(id.as_bytes())[..20]))
    }

    pub(crate) async fn managed_session(&mut self, caller: Option<&str>, workspace: Option<&str>, request: SessionRequest) -> Result<Value> {
        let policy = Policy::read(&self.private_directory)?.ok_or_else(|| problem("SESSION_LAUNCH_POLICY_REQUIRED"))?;
        self.authorized_controller(&policy, caller, workspace)?;
        let id = request.id();
        if !identifier(id) { return Err(problem("SESSION_OPERATION_ID_INVALID")); }
        let store = Store::anchored(self.private_directory.clone(), STATE, true)?;
        let mut records = jobs(&store)?;
        if let Some(job) = records.get(id) {
            if job.selection.workspace != policy.workspace_id || !policy.peers.contains_key(&job.selection.peer) {
                return Err(problem("SESSION_PEER_NOT_AUTHORIZED"));
            }
            if !matches!(request, SessionRequest::Start {..}) {
                let job = job.clone();
                return match request {
                    SessionRequest::Status {..} => self.managed_status(id, &job).await,
                    SessionRequest::Stop {..} => self.stop_managed(&store, &mut records, id, job).await,
                    SessionRequest::Start {..} => unreachable!(),
                };
            }
        }
        match &request {
            SessionRequest::Start {peer, ..} => self.start_managed(&policy, &store, &mut records, id, peer).await,
            _ => Err(problem("SESSION_OPERATION_NOT_FOUND")),
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Connect {
    pub(crate) async fn managed_session(&mut self, _:Option<&str>, _:Option<&str>, _:SessionRequest) -> Result<Value> {
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
        if local != "--local" || id_flag != "--id" { return Err(problem("SESSION_ARGUMENT_INVALID")); }
        let request = match (mode.as_str(), rest) {
            ("start", [flag, peer]) if flag == "--peer" => SessionRequest::Start {operation_id:id.clone(), peer:peer.clone()},
            ("status", []) => SessionRequest::Status {operation_id:id.clone()},
            ("stop", []) => SessionRequest::Stop {operation_id:id.clone()},
            _ => return Err(problem("SESSION_ARGUMENT_INVALID")),
        };
        let registry = std::path::absolute(registry).map_err(|_|problem("SESSION_ARGUMENT_INVALID"))?;
        let executor = tokio::runtime::Builder::new_current_thread().enable_all().build()
            .map_err(|_|problem("EXECUTOR_FAILED"))?;
        executor.block_on(async {
            let mut connect = Connect::open(&registry)?;
            let policy = Policy::read(&connect.private_directory)?.ok_or_else(||problem("SESSION_LAUNCH_POLICY_REQUIRED"))?;
            connect.managed_session(Some(&policy.controller), Some(&policy.workspace_id), request).await
        })
    })();
    result.unwrap_or_else(|error| json!({"ok":false,"state":"FAILED","error":error}))
}

#[cfg(all(test, target_os = "linux"))]
#[path = "participant_managed_session_http_tests.rs"]
mod tests;
