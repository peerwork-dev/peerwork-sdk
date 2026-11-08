//! Explicit administrator-selected local inputs, never caller-selected paths.
use crate::{
    kernel_client::ArchiveMigrationSelection,
    participant::{ParticipantError, Result},
};
use peerwork_core::{
    canonical::{canonical, Path as CanonicalPath},
    crypto::sha256_hex,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MigrationSource {
    Checkpoint {
        workspace_id: String,
        path: PathBuf,
        sha256: String,
    },
    LegacyCache {
        workspace_id: String,
        state_directory: PathBuf,
        plan_path: Option<PathBuf>,
    },
}
fn invalid() -> ParticipantError {
    ParticipantError::local("MIGRATION_SOURCE_INVALID", "CONFIGURATION")
}
pub(crate) fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
impl MigrationSource {
    pub fn workspace_id(&self) -> &str {
        match self {
            Self::Checkpoint { workspace_id, .. } | Self::LegacyCache { workspace_id, .. } => {
                workspace_id
            }
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let path = |p: &PathBuf| {
            p.is_absolute()
                && p.to_str()
                    .is_some_and(|s| s.len() <= 4096 && !s.contains('\0'))
        };
        if !crate::workspace_urls::token(self.workspace_id()) {
            return Err(invalid());
        }
        match self {
            Self::Checkpoint {
                path: p, sha256, ..
            } if path(p) && digest(sha256) => Ok(()),
            Self::LegacyCache {
                state_directory,
                plan_path,
                ..
            } if path(state_directory) && plan_path.as_ref().is_none_or(path) => Ok(()),
            _ => Err(invalid()),
        }
    }
    /// Descriptor-bound handle. Changing workspace/path/hash creates a new ID;
    /// reconfiguration cannot silently retarget an admitted operation.
    pub fn source_id(&self) -> Result<String> {
        self.validate()?;
        Ok(sha256_hex(
            canonical(
                &json!({"domain":"peerwork.migration-source.v1","source":self}),
                CanonicalPath::STRUCTURED,
            )
            .map_err(|_| invalid())?
            .as_bytes(),
        ))
    }
    pub(crate) fn public_info(&self) -> Result<Value> {
        Ok(
            json!({"source_id":self.source_id()?,"workspace_id":self.workspace_id(),"kind":match self{Self::Checkpoint{..}=>"CHECKPOINT",Self::LegacyCache{..}=>"LEGACY_CACHE"}}),
        )
    }
    pub(crate) fn selection(&self, key: &str, name: Option<String>) -> ArchiveMigrationSelection {
        let mut selected = ArchiveMigrationSelection {
            workspace_id: self.workspace_id().into(),
            idempotency_key: key.into(),
            checkpoint_path: None,
            state_dir: None,
            plan_path: None,
            read_only_snapshot: false,
            name,
            expected_checkpoint_sha256: None,
        };
        match self {
            Self::Checkpoint { path, sha256, .. } => {
                selected.checkpoint_path = Some(path.clone());
                selected.expected_checkpoint_sha256 = Some(sha256.clone());
            }
            Self::LegacyCache {
                state_directory,
                plan_path,
                ..
            } => {
                selected.state_dir = Some(state_directory.clone());
                selected.plan_path = plan_path.clone();
                selected.read_only_snapshot = true;
            }
        }
        selected
    }
}
pub(crate) fn validate_sources(sources: &[MigrationSource]) -> Result<()> {
    if sources.len() > 8 {
        return Err(invalid());
    }
    let mut ids = std::collections::BTreeSet::new();
    for source in sources {
        if !ids.insert(source.source_id()?) {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(crate) fn resolve(
    sources: &[MigrationSource],
    workspace: &str,
    id: &str,
    key: &str,
    name: Option<String>,
) -> Result<ArchiveMigrationSelection> {
    let source = sources
        .iter()
        .find(|s| s.workspace_id() == workspace && s.source_id().is_ok_and(|v| v == id))
        .ok_or_else(|| ParticipantError::local("MIGRATION_SOURCE_NOT_CONFIGURED", "PREPARATION"))?;
    if matches!(source, MigrationSource::Checkpoint { .. }) && name.is_some() {
        return Err(ParticipantError::local(
            "MIGRATION_NAME_IN_CHECKPOINT",
            "VALIDATION",
        ));
    }
    Ok(source.selection(key, name))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptors_pin_paths_workspace_and_checkpoint_hash_without_disclosing_paths() {
        let source = MigrationSource::Checkpoint {
            workspace_id: "w".repeat(43),
            path: std::env::temp_dir().join("private-checkpoint"),
            sha256: "a".repeat(64),
        };
        let id = source.source_id().unwrap();
        let info = source.public_info().unwrap();
        assert!(info.get("path").is_none());
        let selected = resolve(
            &[source.clone()],
            source.workspace_id(),
            &id,
            "original",
            None,
        )
        .unwrap();
        assert_eq!(
            selected.expected_checkpoint_sha256.as_deref(),
            Some("a".repeat(64).as_str())
        );
        let changed = MigrationSource::Checkpoint {
            workspace_id: source.workspace_id().into(),
            path: std::env::temp_dir().join("other-checkpoint"),
            sha256: "a".repeat(64),
        };
        assert_ne!(id, changed.source_id().unwrap());
        assert_eq!(
            resolve(&[changed], source.workspace_id(), &id, "original", None)
                .err()
                .unwrap()
                .code,
            "MIGRATION_SOURCE_NOT_CONFIGURED"
        );
        assert!(resolve(&[source.clone()], &"x".repeat(43), &id, "original", None).is_err());
        assert!(validate_sources(&[source.clone(), source]).is_err());
    }
}
