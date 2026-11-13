//! Aliases are addressing conveniences, not grants. An exact instance in a
//! selected Space uses the existing client and current service resolution.
use super::*;
impl AgentTools {
    pub(super) async fn select_instance(&self, selector: &str, request: &AgentRequest) -> Result<Self> {
        let (workspace, instance) = match selector.split_once('/') {
            Some((workspace, instance)) if token(instance) => (self.selected_workspace(Some(workspace))?, instance),
            None if token(selector) => (self.selected_workspace(None)?, selector),
            _ => return Err(invalid("PROTOCOL_ALIAS_UNKNOWN_USE_ALIAS_OR_WORKSPACE_INSTANCE")),
        };
        let mut selected = self.clone();
        // Reusing an alias's explicit delegate must not evade its limits by
        // spelling the same instance as an ID instead.
        let existing: Vec<_> = self.profile.protocols.iter().filter(|(_, scope)|
            scope.workspace_id.as_deref() == Some(&workspace) && scope.instance_id.as_deref() == Some(instance)).collect();
        if existing.len() > 1 {
            let mut bindings=std::collections::BTreeSet::new();
            for (alias, _) in &existing {
                let client=self.protocol_client(alias)?;
                let binding=if let Some(binding)=client.attached_namespace_binding(){binding}else{crate::communication_runtime::canonical_binding(&client.call(json!({"method":"binding"})).await?).to_string()};
                bindings.insert(binding);
            }
            if bindings.len()>1 {return Err(invalid("SELECT_PROTOCOL_ALIAS_FOR_CONFIGURED_INSTANCE"));}
        }
        let (scope, client) = if let Some((alias, scope)) = existing.first() {
            ((*scope).clone(), self.protocol_client(alias)?.clone())
        } else {
            // A metadata route may be broader than the selected sender. It
            // resolves the instance but never becomes an action credential.
            let client = &self.client;
            let original_id = match request {
                AgentRequest::Act { operation_id, .. } | AgentRequest::Status { operation_id, .. } | AgentRequest::Recover { operation_id, .. } => Some(operation_id),
                _ => None,
            };
            if let Some(id) = original_id {
                selected.profile.protocols.insert(selector.into(), Scope { workspace_id: Some(workspace.clone()), instance_id: Some(instance.into()), ..Default::default() });
                selected.protocol_clients.insert(selector.into(), client.clone());
                if let Some((_, scope, _, _)) = selected.original_protocol_operation(selector, id).await? {
                    let scope=scope.clone();selected.profile.protocols.insert(selector.into(), scope);return Ok(selected);
                }
                if !matches!(request, AgentRequest::Act { .. }) {return Err(invalid("OPERATION_NOT_FOUND"));}
            }
            let observed = self.read_client(self.directory_client(&workspace), "structure.instance.resolve", Scope { workspace_id: Some(workspace.clone()), ..Default::default() }, serde_json::json!({"instance_id":instance})).await?;
            let digest = observed["default_binding"]["protocol_digest"].as_str()
                .or_else(|| observed["instance"]["protocol_digest"].as_str())
                .ok_or_else(|| invalid("PROTOCOL_RESOLUTION_FAILED"))?;
            (Scope { workspace_id: Some(workspace), instance_id: Some(instance.into()), protocol_digest: Some(digest.into()) }, client.clone())
        };
        selected.profile.protocols.insert(selector.into(), scope);
        selected.protocol_clients.insert(selector.into(), client);
        Ok(selected)
    }
}
