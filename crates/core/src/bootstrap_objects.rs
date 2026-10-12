//! Native owner-create object construction from pinned, embedded collaboration
//! presets. No Node process or mutable external preset source is used at runtime.
//! This constructs data only; signed policy and complete replay remain separate.

use crate::{
    crypto::{decode_base64url, sha256_hex},
    full_manifest::validate_full_manifest,
    wire_json::parse_wire_json_bounded,
};
use serde_json::{json, Value};
use thiserror::Error;

const EMBEDDED: &str = include_str!("../../../conformance/bootstrap-presets.json");
const EXPECTED_SOURCE: &str = "2e85ed64b4ff63737cfe5fc2fd47f270dc8bb488533a5a287a0270d5702223bd";
const ENTRIES: [&str; 6] = [
    "discussion",
    "wiki",
    "task",
    "hostedService",
    "externalService",
    "outputs",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapObjectsError {
    #[error("owner-create input or embedded preset is invalid")]
    Invalid,
}

pub struct OwnerBootstrapObjects {
    operation: Value,
    scopes: Vec<Value>,
}
impl OwnerBootstrapObjects {
    pub fn operation(&self) -> &Value {
        &self.operation
    }
    pub fn scopes(&self) -> &[Value] {
        &self.scopes
    }
}

/// `instance_ids` are fresh opaque IDs made and durably associated by the
/// runtime before signing. On retry, the exact signed request is reused.
pub fn owner_bootstrap_objects(
    name: &str,
    workspace_id: &str,
    owner_actor: &str,
    created: u64,
    instance_ids: &[String; 6],
) -> Result<OwnerBootstrapObjects, BootstrapObjectsError> {
    owner_bootstrap_objects_with_visibility(
        name,
        workspace_id,
        owner_actor,
        created,
        instance_ids,
        "PRIVATE",
    )
}

pub fn owner_bootstrap_objects_with_visibility(
    name: &str,
    workspace_id: &str,
    owner_actor: &str,
    created: u64,
    instance_ids: &[String; 6],
    visibility: &str,
) -> Result<OwnerBootstrapObjects, BootstrapObjectsError> {
    let bad = || BootstrapObjectsError::Invalid;
    if !matches!(visibility, "PRIVATE" | "PUBLIC")
        || name.is_empty()
        || name.len() > 240
        || !token(workspace_id)
        || !token(owner_actor)
        || created > 9_007_199_254_740_991
        || instance_ids.iter().any(|id| !token(id))
        || instance_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != 6
        || instance_ids.iter().any(|id| id == workspace_id)
    {
        return Err(bad());
    }
    let fixture: Value = serde_json::from_str(EMBEDDED).map_err(|_| bad())?;
    if fixture["source_sha256"] != EXPECTED_SOURCE {
        return Err(bad());
    }
    let entries = fixture["entries"].as_array().ok_or_else(bad)?;
    if entries.len() != ENTRIES.len() {
        return Err(bad());
    }
    let mut objects = vec![json!({"kind":"workspaces","id":workspace_id,"revision":1,
        "provenance":"AUTHOR_SIGNED","value":{"id":workspace_id,"name":name,
            "visibility":visibility,"owner":owner_actor,"created":created}})];
    let mut scopes = Vec::with_capacity(6);
    for (index, entry) in entries.iter().enumerate() {
        if entry["entrypoint"] != ENTRIES[index] {
            return Err(bad());
        }
        let manifest = entry.get("manifest").ok_or_else(bad)?;
        let manifest_wire = serde_json::to_vec(manifest).map_err(|_| bad())?;
        let parsed = parse_wire_json_bounded(&manifest_wire, 40, 196_608).map_err(|_| bad())?;
        let canonical = validate_full_manifest(&parsed).map_err(|_| bad())?;
        let digest = sha256_hex(canonical.as_bytes());
        if entry["digest"] != digest {
            return Err(bad());
        }
        let instance = &instance_ids[index];
        objects.push(json!({"kind":"protocols","id":digest,"revision":1,
            "provenance":"AUTHOR_SIGNED","value":{"workspace_id":workspace_id,
                "digest":digest,"manifest":manifest,"resolved_manifest":manifest}}));
        objects.push(json!({"kind":"instances","id":instance,"revision":1,
            "provenance":"AUTHOR_SIGNED","value":{"id":instance,"workspace_id":workspace_id,
                "protocol_digest":digest,"origin_entrypoint":ENTRIES[index],
                "semantics":"peerwork.kernel.v1","state":manifest["initial_state"],
                "revision":0,"event_revision":0,"created":created}}));
        let mut roles = Vec::<String>::new();
        let active = manifest["role_conflicts"].as_array().ok_or_else(bad)?;
        let historical = manifest["historical_role_conflicts"]
            .as_array()
            .ok_or_else(bad)?;
        for role in manifest["protocol_roles"].as_array().ok_or_else(bad)? {
            let role = role.as_str().ok_or_else(bad)?;
            let conflicts = active.iter().chain(historical).any(|pair| {
                pair.as_array().is_some_and(|pair| {
                    pair.len() == 2
                        && pair.iter().any(|r| r == role)
                        && pair.iter().any(|r| {
                            r.as_str()
                                .is_some_and(|r| r != role && roles.iter().any(|old| old == r))
                        })
                })
            });
            if !conflicts {
                roles.push(role.to_owned());
            }
        }
        let actions: Vec<_> = manifest["actions"]
            .as_array()
            .ok_or_else(bad)?
            .iter()
            .map(|action| action["id"].as_str().map(str::to_owned).ok_or_else(bad))
            .collect::<Result<_, _>>()?;
        scopes.push(json!({"instance_id":instance,"actions":actions,
            "protocol_roles":roles,"capabilities":manifest["capabilities"]}));
    }
    Ok(OwnerBootstrapObjects {
        operation: json!({"v":1,"kind":"BOOTSTRAP","input":{},"objects":objects}),
        scopes,
    })
}

fn token(value: &str) -> bool {
    value.len() == 43 && decode_base64url(value).is_ok_and(|bytes| bytes.len() == 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::base64url;
    #[test]
    fn pinned_collaboration_presets_form_owner_bootstrap_objects() {
        let workspace = base64url(&[7; 32]);
        let owner = base64url(&[8; 32]);
        let ids = std::array::from_fn(|i| base64url(&[i as u8 + 20; 32]));
        let result =
            owner_bootstrap_objects("Test workspace", &workspace, &owner, 100, &ids).unwrap();
        assert_eq!(result.operation()["objects"].as_array().unwrap().len(), 13);
        assert_eq!(result.scopes().len(), 6);
        let public = owner_bootstrap_objects_with_visibility(
            "Test workspace",
            &workspace,
            &owner,
            100,
            &ids,
            "PUBLIC",
        )
        .unwrap();
        assert_eq!(
            public.operation()["objects"][0]["value"]["visibility"],
            "PUBLIC"
        );
        assert!(owner_bootstrap_objects_with_visibility(
            "Test workspace",
            &workspace,
            &owner,
            100,
            &ids,
            "public"
        )
        .is_err());
        assert_eq!(
            result.operation()["objects"][1]["id"],
            "e31188a871138c8065682517931fba8c3fbd288516cda6c7aad88ff70c135c17"
        );
        assert!(owner_bootstrap_objects("", &workspace, &owner, 100, &ids).is_err());
    }
}
