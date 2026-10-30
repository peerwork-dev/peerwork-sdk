//! Local convenience operations. They reuse native producers and verification;
//! these names are not service actions and cannot extend backend authority.
use crate::{
    kernel_client::{
        PublicationSnapshotSelection, StructureAccessApproval, StructureAccessRequest,
        StructureContentKeyRotation, StructureKeyAcceptance,
    },
    participant::{Invoke, ParticipantError, Result},
};
use peerwork_core::structure_execution::{self as native, StructureOperationKind};
use serde_json::{json, Value};

pub(crate) const HELPERS: &[&str] = &[
    "participant.access.approve",
    "participant.access.request",
    "participant.archive.migrate",
    "participant.archive.sources",
    "participant.keys.accept",
    "participant.keys.coordinate",
    "participant.keys.initialize",
    "participant.keys.rotate",
    "participant.publication.publish",
    "participant.protocol.offline",
];
pub(crate) fn maintenance(action: &str) -> bool {
    action == "participant.archive.migrate"
        || action.starts_with("structure.maintenance.")
        || action.starts_with("structure.migration.")
        || action == "structure.workspace.delete"
}
pub(crate) fn kind(action: &str) -> Option<StructureOperationKind> {
    match action {
        "participant.access.approve"
        | "participant.archive.migrate"
        | "participant.keys.coordinate"
        | "participant.keys.rotate"
        | "participant.publication.publish" => Some(StructureOperationKind::Mutation),
        "participant.access.request"
        | "participant.archive.sources"
        | "participant.protocol.offline"
        | "participant.keys.accept"
        | "participant.keys.initialize" => Some(StructureOperationKind::Control),
        _ => native::operation_kind(action),
    }
}
pub(crate) fn instance_scoped(action: &str) -> bool {
    action == "participant.publication.publish" || native::is_instance_scoped(action)
}
pub(crate) enum Selection {
    Request(StructureAccessRequest),
    Approve(StructureAccessApproval),
    Accept(StructureKeyAcceptance),
    Rotate(StructureContentKeyRotation),
    Coordinate(String),
    Initialize(String),
    Publish(PublicationSnapshotSelection),
    Migrate {
        workspace: String,
        source_id: String,
        name: Option<String>,
    },
    Sources(String),
    Offline {
        operation: String,
        input: Value,
    },
}
fn invalid() -> ParticipantError {
    ParticipantError::local("HELPER_SELECTION_INVALID", "VALIDATION")
}
pub(crate) fn selection(r: &Invoke, idempotency_key: &str) -> Result<Selection> {
    // A caller may not hide a second scope or an arbitrary native command ID
    // in helper data. Local paths/identity selectors are deliberately absent.
    if !HELPERS.contains(&r.action.as_str())
        || r.plaintext_contents.is_some()
        || r.plaintext_message.is_some()
        || r.expected_instance_revision.is_some()
        || !r.exact_input_refs.is_empty()
        || r.body.as_object().is_none_or(|o| {
            [
                "workspace_id",
                "instance_id",
                "protocol_digest",
                "idempotency_key",
                "command_id",
            ]
            .iter()
            .any(|k| o.contains_key(*k))
        })
    {
        return Err(invalid());
    }
    if r.action == "participant.protocol.offline" {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Offline {
            operation: String,
            input: Value,
        }
        if r.scope != crate::participant::Scope::default()
            || r.expected_workspace_revision.is_some()
        {
            return Err(invalid());
        }
        let selected: Offline = serde_json::from_value(r.body.clone()).map_err(|_| invalid())?;
        if !["compatibility", "fixture", "simulate", "plan"].contains(&selected.operation.as_str())
        {
            return Err(invalid());
        }
        return Ok(Selection::Offline {
            operation: selected.operation,
            input: selected.input,
        });
    }
    let ws = r
        .scope
        .workspace_id
        .as_deref()
        .filter(|s| crate::workspace_urls::token(s))
        .ok_or_else(invalid)?;
    let publication = r.action == "participant.publication.publish";
    if !publication && (r.scope.instance_id.is_some() || r.scope.protocol_digest.is_some()) {
        return Err(invalid());
    }
    if r.expected_workspace_revision.is_some() && r.action != "participant.access.approve" {
        return Err(invalid());
    }
    let mut value = r.body.clone();
    value["workspace_id"] = json!(ws);
    fn parse<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
        serde_json::from_value(v).map_err(|_| invalid())
    }
    Ok(match r.action.as_str() {
        "participant.archive.migrate" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Migrate {
                source_id: String,
                #[serde(default)]
                name: Option<String>,
            }
            let s: Migrate = serde_json::from_value(r.body.clone()).map_err(|_| invalid())?;
            if !crate::participant_migration::digest(&s.source_id)
                || s.name
                    .as_ref()
                    .is_some_and(|n| n.is_empty() || n.encode_utf16().count() > 120)
            {
                return Err(invalid());
            }
            Selection::Migrate {
                workspace: ws.into(),
                source_id: s.source_id,
                name: s.name,
            }
        }
        "participant.archive.sources" => {
            if r.body.as_object().is_none_or(|o| !o.is_empty()) {
                return Err(invalid());
            }
            Selection::Sources(ws.into())
        }
        "participant.access.request" => Selection::Request(parse(value)?),
        "participant.access.approve" => {
            if value.get("expected_workspace_revision").is_some() {
                return Err(invalid());
            }
            value["expected_workspace_revision"] = json!(r.expected_workspace_revision);
            Selection::Approve(parse(value)?)
        }
        "participant.keys.accept" => Selection::Accept(parse(value)?),
        "participant.keys.rotate" => {
            value["idempotency_key"] = json!(idempotency_key);
            Selection::Rotate(parse(value)?)
        }
        "participant.keys.coordinate" | "participant.keys.initialize" => {
            if r.body.as_object().is_none_or(|o| !o.is_empty()) {
                return Err(invalid());
            }
            if r.action.ends_with("initialize") {
                Selection::Initialize(ws.into())
            } else {
                Selection::Coordinate(ws.into())
            }
        }
        "participant.publication.publish" => {
            value["instance_id"] = json!(r.scope.instance_id.as_deref().ok_or_else(invalid)?);
            value["protocol_digest"] =
                json!(r.scope.protocol_digest.as_deref().ok_or_else(invalid)?);
            value["idempotency_key"] = json!(idempotency_key);
            Selection::Publish(parse(value)?)
        }
        _ => return Err(invalid()),
    })
}
pub(crate) fn validate(r: &Invoke) -> Result<()> {
    if HELPERS.contains(&r.action.as_str()) {
        selection(r, "validation")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::participant::{Capability, Scope};
    #[test]
    fn helpers_cannot_smuggle_scope_keys_paths_or_unused_fields() {
        let scope = Scope {
            workspace_id: Some("w".repeat(43)),
            ..Default::default()
        };
        let mut r = Invoke::new(
            "initialize",
            "participant.keys.initialize",
            scope.clone(),
            json!({}),
        );
        Capability::owner().authorize(&r).unwrap();
        for body in [
            json!({"workspace_id":"other"}),
            json!({"state_dir":"/other"}),
            json!({"idempotency_key":"different"}),
            json!({"command_id":"different"}),
        ] {
            r.body = body;
            assert!(Capability::owner().authorize(&r).is_err());
        }
        r.body = json!({});
        r.plaintext_message = Some("ignored text".into());
        assert!(r.validate().is_err());
        let mut worker = Capability::owner();
        worker.instance_ids = Some(["i".repeat(43)].into());
        let approve = Invoke::new(
            "approve",
            "participant.access.approve",
            scope,
            json!({"request_jws":"request","deliver_content_keys":false}),
        );
        assert_eq!(
            worker.authorize(&approve).unwrap_err().code,
            "LOCAL_SCOPE_DENIED"
        );
    }
}
