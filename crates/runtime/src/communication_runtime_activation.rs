//! Authenticated lifecycle mutation and read-only presentation continuation.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    client_name: String,
    source_binding: Value,
    source_group: Value,
    options: WatchOptions,
    target: Value,
    operation_id: String,
    expected_generation: u64,
    #[serde(default)]
    select_session: bool,
}

pub(super) use crate::notification_delivery::activation::member_key;

struct Group {
    source:String,
    members:Vec<String>,
    bindings:Vec<WatchOptions>,
    descriptor:Value,
}

fn group(client:&ParticipantClient,mut bindings:Vec<WatchOptions>)->Result<Group> {
    bindings.sort_by(|a,b|(&a.workspace_id,&a.mailbox_id,&a.membership_id).cmp(&(&b.workspace_id,&b.mailbox_id,&b.membership_id)));
    let selected=bindings.iter().map(|w|json!([w.workspace_id,w.mailbox_id,w.membership_id])).collect::<Vec<_>>();
    if bindings.is_empty()||bindings.len()>8||selected.windows(2).any(|v|v[0]==v[1]) {return Err(local("PRESENTATION_GROUP_SELECTION_REQUIRED"));}
    let source=crate::notification_delivery::activation::source_key(client,&bindings);
    let mut members=bindings.iter().map(|w|member_key(client,client.local_namespace(),w)).collect::<Vec<_>>();members.sort();
    let descriptor=json!({"source":source,"members":selected,"bindings":bindings,
        "state_binding":client.state_binding(),"namespace":client.local_namespace()});
    Ok(Group{source,members,bindings,descriptor})
}

impl Runtime {
    async fn presentation_source(&self, client:&ParticipantClient, options:&WatchOptions) -> Result<Group> {
        options.authorize(client.capability())?;
        // Rebind temporarily disables its watches. Classify that interval as
        // pending, so an aborted move can resume the original activation.
        let member=member_key(client,client.local_namespace(),options);
        if self.notifications.store.presentation_pending("",&[member])? {return Err(local("PRESENTATION_REBIND_PENDING"));}
        // Resolve the complete persisted namespace using the already-held
        // original owner. The calling view may be narrower, but cannot elect
        // a competing partial group for the same notification owner.
        let owner=self.owners.values().find(|owner|owner.state_binding()==client.state_binding())
            .ok_or_else(||local("ORIGINAL_RUNTIME_BINDING_CHANGED"))?;
        let original=owner.namespace_view(client.local_namespace(),owner.capability().clone())?;
        let bindings=original.watch_bindings().await?;
        if !bindings.iter().any(|watch|watch==options) {
            return Err(local("PRESENTATION_SOURCE_CHANGED"));
        }
        let bindings=bindings.into_iter().filter(|watch|watch.host_destination==options.host_destination).collect::<Vec<_>>();
        if bindings.iter().any(|watch|watch.authorize(client.capability()).is_err()) {
            return Err(local("PRESENTATION_GROUP_SELECTION_REQUIRED"));
        }
        group(client,bindings)
    }

    pub(super) async fn presentation_activate(&self, request:Intent) -> Result<Value> {
        let session=self.sessions.read().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?
            .iter().find(|session|session.name==request.client_name).cloned()
            .ok_or_else(||local("ORIGINAL_RUNTIME_BINDING_CHANGED"))?;
        let client=&session.client;
        let expected=crate::agent_delivery_status::binding(&json!({"actor_id":client.actor_id(),"origin":client.origin(),
            "receiving_binding":{"client_name":session.name,"client_generation":session.generation,
                "namespace":client.local_namespace(),"engine_digest":self.engine_bindings.get(client.state_binding()),
                "state_binding":client.state_binding()}}),&serde_json::to_value(&request.options).unwrap());
        if request.source_binding!=expected {return Err(local("ORIGINAL_RUNTIME_BINDING_CHANGED"));}
        let group=self.presentation_source(client,&request.options).await?;
        if request.source_group!=group.descriptor {return Err(local("PRESENTATION_GROUP_SELECTION_REQUIRED"));}
        let host_session = request.target.get("host_session");
        let valid_session = host_session.is_some_and(|value| value.as_str().is_some_and(|digest|
            digest.len()==64 && digest.bytes().all(|byte|byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))));
        if !request.target.is_object() || !matches!(request.target["kind"].as_str(),Some("MCP_STDIO_CHANNEL"|"MCP_BACKGROUND_TOOL"))
            || request.target["registration_id"].as_str().is_none_or(|id|!identifier(id))
            || request.target.as_object().is_none_or(|object|object.len()!=3+usize::from(host_session.is_some()))
            || host_session.is_some() && (!valid_session || request.target["kind"]!="MCP_STDIO_CHANNEL")
            || request.select_session && !valid_session
            || !request.target.get("host_destination").is_some_and(Value::is_null) {
            return Err(local("PRESENTATION_TARGET_INVALID"));
        }
        // A presentation activation cannot itself move a mailbox to another
        // destination. The existing rebind must first commit that selection.
        if request.options.host_destination.as_deref()!=request.target["host_destination"].as_str()
            || request.target.get("host_destination").is_some_and(|v|!v.is_null()&&!v.is_string()) {
            return Err(local("PRESENTATION_TARGET_BINDING_MISMATCH"));
        }
        let previous=self.notifications.store.presentation_generation(&group.source)?;
        let result=self.notifications.store.presentation_replace(&group.source,&group.members,&request.operation_id,
            request.expected_generation,&request.target,request.select_session)?;
        if result["current_generation"].as_u64()!=Some(previous) {
            for options in &group.bindings {
                let channel=crate::communication_notifications::channel_key(&crate::communication_notifications::owner(client,options),options,session.generation);
                self.notifications.forget_channel_observation(&channel)?;
            }
        }
        self.notifications.changed.notify_waiters();
        Ok(result)
    }

    pub(super) async fn presentation_status(&self, client:&ParticipantClient, options:&WatchOptions) -> Result<Value> {
        let group=self.presentation_source(client,options).await?;
        let generation=self.notifications.store.presentation_generation(&group.source)?;
        let pending=self.notifications.store.presentation_pending(&group.source,&group.members)?;
        Ok(json!({"state":if pending{"REBIND_PENDING"}else if !self.notifications.store.presentation_managed(&group.source)?{"UNMANAGED"}else{"MANAGED"},"source":group.source,"group":group.descriptor,"current_generation":generation}))
    }

    pub(super) async fn presentation_resume(&self, client:&ParticipantClient, options:&WatchOptions, activation:&PresentationActivation) -> Result<Value> {
        let group=self.presentation_source(client,options).await?;
        self.notifications.store.presentation_resume(&group.source,activation)
    }

    pub(super) async fn presentation_admit(&self, client:&ParticipantClient, options:&WatchOptions, activation:Option<&PresentationActivation>) -> Result<crate::notification_delivery::activation::Admission> {
        let group=self.presentation_source(client,options).await?;
        if activation.is_some_and(|a|a.target["host_destination"].as_str()!=options.host_destination.as_deref()) {return Err(local("PRESENTATION_TARGET_BINDING_MISMATCH"));}
        let admission=crate::notification_delivery::activation::Admission{source:group.source,members:group.members,activation:activation.cloned()};
        self.notifications.store.presentation_check(&admission)?;
        Ok(admission)
    }

    pub(super) async fn presentation_legacy_validate(&self, client:&ParticipantClient) -> Result<()> {
        for options in client.watch_bindings().await? {
            let group=self.presentation_source(client,&options).await?;
            self.notifications.store.presentation_check(&crate::notification_delivery::activation::Admission{source:group.source,members:group.members,activation:None})?;
        }
        Ok(())
    }

    pub(super) async fn presentation_validate(&self, client:&ParticipantClient, options:&WatchOptions, activation:Option<&PresentationActivation>, batch:&str, revision:u64) -> Result<bool> {
        let group=self.presentation_source(client,options).await?;
        if activation.is_some_and(|a|a.target["host_destination"].as_str()!=options.host_destination.as_deref()) {
            return Err(local("PRESENTATION_TARGET_BINDING_MISMATCH"));
        }
        self.notifications.store.presentation_notification_allowed(&group.source,&group.members,activation,
            &crate::communication_notifications::owner(client,options),batch,revision)
    }
}
