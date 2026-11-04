//! Binding transitions shared by the offline and resident coordinators.
//! The caller owns exclusion, durable job writes and network scheduling. These
//! Only an explicitly scheduled work item performs network IO. Local steps
//! never open state, create another access session or change an operation ID.
use super::*;

/// Only the remote half of one selected mailbox replacement. The job owns all
/// durable facts; this cursor is disposable and may restart after interruption.
/// A resident driver schedules one returned work item, then applies its result
/// on its InboxStore owner task. It must persist every changed job before asking
/// for the next work item. No SQLite borrow or owner mutex crosses network IO.
pub(super) struct ReplacementProgress {
    phase: ReplacementPhase,
    needs_save: bool,
    issued: Option<String>,
}
#[derive(Clone, Copy)]
enum ReplacementPhase { Inspect, Pulse, Reports, Submit, Complete }
#[derive(Serialize)]
pub(super) enum ReplacementWork {
    Inspect { workspace: String, mailbox: String },
    Pulse { workspace: String, body: Value },
    Report { workspace: String, body: Value, call_id: String, version: u64 },
    Freeze,
    Submit { wire: String, claim_id: String },
}
impl ReplacementWork {
    fn token_for(&self, scope: &Subscription) -> Result<String> {
        let wire = serde_json::to_vec(&(scope, self)).map_err(|_| error("HOST_REBIND_STATE_INVALID"))?;
        Ok(sha256_hex(&wire))
    }
    pub(super) async fn execute(&self, access: &KernelAccess) -> Result<Value> {
        match self {
            Self::Inspect { workspace, mailbox } => call(access, "structure.mailbox.get",
                workspace, json!({"mailbox_id":mailbox}), None).await,
            Self::Pulse { workspace, body } => call(access, "structure.mailbox.pulse",
                workspace, body.clone(), None).await,
            Self::Report { workspace, body, .. } => call(access, "structure.mailbox.report",
                workspace, body.clone(), None).await,
            Self::Submit { wire, claim_id } => execute(access, wire, Some(claim_id)).await,
            Self::Freeze => Ok(Value::Null),
        }
    }
    pub(super) fn before_save_boundary(&self) -> Option<&'static str> {
        match self {
            Self::Submit { .. } => Some("CLAIM_CONFIRMED_BEFORE_SAVE"),
            _ => None,
        }
    }
    pub(super) fn after_save_boundary(&self) -> Option<&'static str> {
        match self {
            Self::Freeze => Some("CLAIM_FROZEN"),
            _ => None,
        }
    }
}
impl ReplacementProgress {
    pub(super) fn new(scope: &Subscription) -> Self {
        Self { phase: if scope.confirmed.is_some() { ReplacementPhase::Complete }
            else if scope.claim_wire.is_some() { ReplacementPhase::Submit }
            else { ReplacementPhase::Inspect }, needs_save: false, issued: None }
    }
    pub(super) fn next(&mut self, scope: &Subscription, inbox: &InboxStore,
        identity: &KernelIdentity) -> Result<Option<ReplacementWork>> {
        if self.needs_save { return Err(error("HOST_REBIND_PERSISTENCE_REQUIRED")); }
        if self.issued.is_some() { return Err(error("HOST_REBIND_WORK_PENDING")); }
        let workspace = scope.old.workspace_id.clone();
        let work = match self.phase {
            ReplacementPhase::Complete => return Ok(None),
            ReplacementPhase::Inspect => {
                if scope.old.host_destination.is_some() { inbox.rebind_reports_unblocked(&scope.old)?; }
                ReplacementWork::Inspect { workspace, mailbox: scope.old.mailbox_id.clone() }
            },
            ReplacementPhase::Pulse => ReplacementWork::Pulse { workspace,
                body: json!({"mailbox_id":scope.old.mailbox_id,"receiver_id":scope.expected.receiver_id,
                    "epoch":scope.expected.epoch,"ready":false,"execution_state":"OFFLINE"}) },
            ReplacementPhase::Reports => {
                match if scope.old.host_destination.is_some() {
                    inbox.pending_host_report(identity, &scope.namespace, &scope.old)?
                } else { None } {
                    Some((call_id, version, report)) => ReplacementWork::Report { workspace, call_id, version,
                        body: json!({"mailbox_id":scope.old.mailbox_id,"receiver_id":scope.expected.receiver_id,
                            "epoch":scope.expected.epoch,"report":report}) },
                    None => ReplacementWork::Freeze,
                }
            },
            ReplacementPhase::Submit => ReplacementWork::Submit {
                wire: scope.claim_wire.clone().ok_or_else(|| error("HOST_REBIND_STATE_INVALID"))?,
                claim_id: scope.claim_id.clone(),
            },
        };
        self.issued = Some(work.token_for(scope)?);
        Ok(Some(work))
    }
    /// Acknowledge only after the complete sealed job has been durably saved.
    /// Save failures retain the barrier and do not authorize submission.
    pub(super) fn saved(&mut self) {
        self.needs_save = false;
    }
    /// Returns true when the sealed job changed and must be saved before any
    /// subsequent submission. A failed result leaves its original claim intact.
    pub(super) fn apply(&mut self, work: &ReplacementWork, value: &Value,
        scope: &mut Subscription, inbox: &mut InboxStore, identity: &KernelIdentity,
        actor: &str, destination: &str) -> Result<bool> {
        if self.needs_save { return Err(error("HOST_REBIND_PERSISTENCE_REQUIRED")); }
        if self.issued.as_deref() != Some(work.token_for(scope)?.as_str()) {
            return Err(error("HOST_REBIND_WORK_SELECTION_CHANGED"));
        }
        let changed: Result<bool> = match work {
            ReplacementWork::Inspect { .. } => {
                let pins = scope.inspect_replacement(&value["mailbox"], actor)?;
                let changed = scope.refresh_epoch_on_retry;
                if changed {
                    inbox.register(&pins)?;
                    scope.expected = Pins::from(&pins);
                    scope.refresh_epoch_on_retry = false;
                }
                self.phase = ReplacementPhase::Pulse;
                Ok(changed)
            },
            ReplacementWork::Pulse { .. } => { self.phase = ReplacementPhase::Reports; Ok(false) },
            ReplacementWork::Report { call_id, version, .. } => {
                inbox.host_reported(&scope.old.workspace_id, &scope.old.mailbox_id, call_id, *version)?;
                Ok(false)
            },
            ReplacementWork::Freeze => {
                scope.claim_wire = Some(scope.replacement_wire(inbox, identity, destination)?);
                self.phase = ReplacementPhase::Submit;
                Ok(true)
            },
            ReplacementWork::Submit { .. } => {
                scope.confirmed = Some(scope.confirmed_replacement(&value["mailbox"], actor, destination)?);
                self.phase = ReplacementPhase::Complete;
                Ok(true)
            },
        };
        let changed = changed?;
        self.issued = None;
        self.needs_save = changed;
        Ok(changed)
    }
}

impl Subscription {
    pub(super) fn inspect_replacement(&self, mailbox: &Value, actor: &str) -> Result<MailboxPins> {
        let epoch = if self.refresh_epoch_on_retry {
            mailbox["epoch"].as_u64().filter(|e| *e >= self.expected.epoch)
                .ok_or_else(|| error("HOST_REBIND_VERIFIED_MAILBOX_MISMATCH"))?
        } else {
            self.expected.epoch
        };
        validate_mailbox(mailbox, &self.expected, actor,
            &self.expected.destination_digest, epoch, self.expected.binding_version)?;
        let mut pins = self.expected.native();
        pins.epoch = epoch;
        Ok(pins)
    }

    pub(super) fn replacement_wire(
        &self, inbox: &InboxStore, identity: &KernelIdentity, destination: &str,
    ) -> Result<String> {
        let binding = Binding {
            namespace: self.namespace.clone(), options: self.old.clone(),
            receiver: self.expected.receiver_id.clone(), claim_id: self.claim_id.clone(),
            claim_wire: None, pins: Some(self.expected.native()),
        };
        let mut body = json!({"claim_command_id":self.claim_id,"mailbox_id":self.old.mailbox_id,
            "receiver_id":self.expected.receiver_id,"expected_epoch":self.expected.epoch,
            "destination_digest":destination,"replace":true,"event_format":peerwork_core::communication::WORKSPACE_EVENT_FORMAT});
        body["continuity_proof"] = json!(inbox.receiver_proof(identity, &binding, &body)?);
        Ok(json!({"action":"structure.mailbox.claim","workspace_id":self.old.workspace_id,
            "command_id":self.claim_id,"body":body}).to_string())
    }

    pub(super) fn confirmed_replacement(&self, mailbox: &Value, actor: &str, destination: &str) -> Result<Pins> {
        let epoch = self.expected.epoch.checked_add(1)
            .ok_or_else(|| error("HOST_REBIND_PINS_INVALID"))?;
        let version = self.expected.binding_version.checked_add(1)
            .ok_or_else(|| error("HOST_REBIND_PINS_INVALID"))?;
        validate_mailbox(mailbox, &self.expected, actor, destination, epoch, version)?;
        let mut confirmed = self.expected.clone();
        confirmed.epoch = epoch;
        confirmed.binding_version = version;
        confirmed.destination_digest = destination.into();
        Ok(confirmed)
    }

    pub(super) fn local_replacement(&self, operation_id: &str, host: &HostBinding) -> Result<HostRebind> {
        let mut new = self.old.clone();
        new.host_destination = Some(host.digest.clone());
        Ok(HostRebind {
            operation_id: operation_id.into(), namespace: self.namespace.clone(),
            old: self.old.clone(), new, expected: self.expected.native(),
            confirmed: self.confirmed.as_ref()
                .ok_or_else(|| error("HOST_REBIND_STATE_INVALID"))?.native(),
            host: host.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_submission_waits_for_durable_save_and_rejects_stale_work() {
        let root = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&root.path().join("identity")).unwrap();
        let origin = "https://example.invalid/";
        let mut inbox = InboxStore::open_local(&root.path().join("inbox"), &identity, origin).unwrap();
        let options = WatchOptions { workspace_id: "w".repeat(43), mailbox_id: "m".repeat(43),
            membership_id: "g".repeat(43), consumer_id: "worker".into(), host_destination: None };
        let namespace = "program:worker";
        let binding = inbox.attach_watch(&identity, namespace, &options).unwrap();
        let pins = MailboxPins { workspace_id: options.workspace_id.clone(), mailbox_id: options.mailbox_id.clone(),
            membership_id: options.membership_id.clone(), receiver_id: binding.receiver,
            epoch: 1, destination_digest: options.destination(identity.actor_id(), origin, namespace),
            binding_version: 1, after_sequence: 0, after_control_sequence: Some(0) };
        inbox.register(&pins).unwrap();
        inbox.disable_watch(namespace, &options).unwrap();
        let mut scope = Subscription { namespace: namespace.into(), old: options,
            expected: Pins::from(&pins), claim_id: "c".repeat(43), claim_wire: None, confirmed: None,
            committed: false, was_enabled: true, rejected: vec![], refresh_epoch_on_retry: false,
            source_client: None };
        let target = "d".repeat(64);
        let mailbox = |destination: &str, epoch, version| json!({"mailbox":{
            "mailbox_id":pins.mailbox_id,"membership_id":pins.membership_id,
            "actor_id":identity.actor_id(),"receiver_id":pins.receiver_id,
            "destination_digest":destination,"epoch":epoch,"binding_version":version}});
        let mut progress = ReplacementProgress::new(&scope);
        let inspect = progress.next(&scope, &inbox, &identity).unwrap().unwrap();
        assert_eq!(progress.next(&scope, &inbox, &identity).err().unwrap().code, "HOST_REBIND_WORK_PENDING");
        let stale = ReplacementWork::Pulse { workspace: scope.old.workspace_id.clone(), body: Value::Null };
        assert_eq!(progress.apply(&stale, &Value::Null, &mut scope, &mut inbox, &identity,
            identity.actor_id(), &target).unwrap_err().code, "HOST_REBIND_WORK_SELECTION_CHANGED");
        assert!(!progress.apply(&inspect, &mailbox(&pins.destination_digest, 1, 1), &mut scope,
            &mut inbox, &identity, identity.actor_id(), &target).unwrap());
        let pulse = progress.next(&scope, &inbox, &identity).unwrap().unwrap();
        assert!(!progress.apply(&pulse, &Value::Null, &mut scope, &mut inbox, &identity,
            identity.actor_id(), &target).unwrap());
        let freeze = progress.next(&scope, &inbox, &identity).unwrap().unwrap();
        assert!(matches!(&freeze, ReplacementWork::Freeze));
        assert!(progress.apply(&freeze, &Value::Null, &mut scope, &mut inbox, &identity,
            identity.actor_id(), &target).unwrap());
        let original_wire = scope.claim_wire.clone().unwrap();
        assert_eq!(progress.next(&scope, &inbox, &identity).err().unwrap().code, "HOST_REBIND_PERSISTENCE_REQUIRED");
        // Both an acknowledged save and a process restart from that saved
        // subscription select the exact original wire and command ID.
        progress.saved();
        let submitted = progress.next(&scope, &inbox, &identity).unwrap().unwrap();
        let mut resumed = ReplacementProgress::new(&scope);
        let recovered = resumed.next(&scope, &inbox, &identity).unwrap().unwrap();
        assert_eq!(submitted.token_for(&scope).unwrap(), recovered.token_for(&scope).unwrap());
        assert_eq!(scope.claim_wire.as_deref(), Some(original_wire.as_str()));
        assert!(progress.apply(&submitted, &mailbox(&target, 2, 2), &mut scope, &mut inbox,
            &identity, identity.actor_id(), &target).unwrap());
        assert_eq!(progress.next(&scope, &inbox, &identity).err().unwrap().code, "HOST_REBIND_PERSISTENCE_REQUIRED");
        progress.saved();
        assert!(progress.next(&scope, &inbox, &identity).unwrap().is_none());
        assert_eq!(progress.apply(&submitted, &mailbox(&target, 2, 2), &mut scope, &mut inbox,
            &identity, identity.actor_id(), &target).unwrap_err().code, "HOST_REBIND_WORK_SELECTION_CHANGED");
    }
}

// Both coordinators use the same no-effect proof and original receiver restart.
impl Subscription {
    pub(super) fn abort_inspection(&self, current:&Value, actor:&str, inbox:&mut InboxStore)->Result<u64> {
        let epoch=current["mailbox"]["epoch"].as_u64().filter(|v|*v>=self.expected.epoch)
            .ok_or_else(||error("HOST_REBIND_VERIFIED_MAILBOX_MISMATCH"))?;
        validate_mailbox(&current["mailbox"],&self.expected,actor,&self.expected.destination_digest,epoch,self.expected.binding_version)?;
        let mut pins=self.expected.native();pins.epoch=epoch;inbox.register(&pins)?;Ok(epoch)
    }
    pub(super) fn restore_aborted_watch(&self,inbox:&InboxStore,operation:&str,decision:Option<&str>,index:usize)->Result<()> {
        let claim=token(json!([operation,decision,index,"abort-watch-restart"]));
        inbox.rebind_restore_watch(&self.namespace,&self.old,&self.expected.receiver_id,self.was_enabled,&claim)
    }
}
