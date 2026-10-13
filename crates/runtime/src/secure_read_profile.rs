//! Protected PUBLIC secure-read profile with two restartable snapshot slots.
//! A complete signed replay and exact ancestor check precede every pointer
//! switch. A failed refresh leaves the previous verified slot intact.

use crate::{
    kernel_identity::KernelIdentity,
    secure_read_access::{
        SecureReadAccess, SecureReadAccessError, SecureReadConfig, VerifiedReadFloor,
    },
    secure_state::SecureStateStore,
    secure_verified_read::TransportReplayedJournal,
};
use peerwork_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureReadProfileConfig {
    pub origin: String,
    pub state_dir: PathBuf,
    pub identity_path: PathBuf,
    pub workspace_id: String,
    /// Required on first contact; later reads use the protected saved pins.
    pub owner_actor_id: Option<String>,
    pub owner_key_id: Option<String>,
    /// Omission chooses the tracked client default SHA-256(local actor ID).
    pub authority: Option<String>,
    #[serde(default)]
    pub required_features: Vec<String>,
    #[serde(default)]
    pub allow_loopback_http: bool,
    #[serde(default = "default_replay_budget")]
    pub max_replay_artifact_bytes: u64,
}

fn default_replay_budget() -> u64 {
    64 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    version: u8,
    origin: String,
    identity_path: PathBuf,
    workspace_id: String,
    authority: String,
    owner_actor_id: String,
    owner_key_id: String,
    required_features: Vec<String>,
    allow_loopback_http: bool,
    current: Option<u8>,
    staged: Option<u8>,
    staged_ready: bool,
    floor: Option<VerifiedReadFloor>,
}

impl ProfileDocument {
    fn valid(&self) -> bool {
        self.version == 1
            && self.current.is_some() == self.floor.is_some()
            && self.current.is_none_or(|slot| slot <= 1)
            && self.staged.is_none_or(|slot| slot <= 1)
            && !matches!((self.current, self.staged), (Some(current), Some(staged)) if current == staged)
            && (!self.staged_ready || self.staged.is_some())
    }
}

pub struct SecureReadProfile {
    config: SecureReadProfileConfig,
}

impl SecureReadProfile {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }

    pub fn read_latest_json(&self) -> Result<String, SecureReadAccessError> {
        self.read_latest_json_with_cancel(&CancellationToken::new())
    }

    pub fn read_latest_json_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<String, SecureReadAccessError> {
        if cancel.is_cancelled() {
            return Err(SecureReadAccessError::Cancelled);
        }
        ensure_private_directory(&self.config.state_dir)?;
        let store = SecureStateStore::open(&self.config.state_dir.join("read.profile"))
            .map_err(|_| SecureReadAccessError::Profile)?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| SecureReadAccessError::Identity)?;
        let mut profile = match store
            .read_exact()
            .map_err(|_| SecureReadAccessError::Profile)?
        {
            Some(wire) => {
                if wire.len() > 16 * 1024 {
                    return Err(SecureReadAccessError::Profile);
                }
                let saved: ProfileDocument =
                    serde_json::from_slice(&wire).map_err(|_| SecureReadAccessError::Profile)?;
                if !saved.valid()
                    || saved.origin != self.config.origin
                    || saved.identity_path != self.config.identity_path
                    || saved.workspace_id != self.config.workspace_id
                    || saved.required_features != self.config.required_features
                    || saved.allow_loopback_http != self.config.allow_loopback_http
                    || self
                        .config
                        .owner_actor_id
                        .as_deref()
                        .is_some_and(|value| value != saved.owner_actor_id)
                    || self
                        .config
                        .owner_key_id
                        .as_deref()
                        .is_some_and(|value| value != saved.owner_key_id)
                    || self
                        .config
                        .authority
                        .as_deref()
                        .is_some_and(|value| value != saved.authority)
                {
                    return Err(SecureReadAccessError::Profile);
                }
                saved
            }
            None => {
                let owner_actor_id = self
                    .config
                    .owner_actor_id
                    .clone()
                    .filter(|value| !value.is_empty())
                    .ok_or(SecureReadAccessError::Profile)?;
                let owner_key_id = self
                    .config
                    .owner_key_id
                    .clone()
                    .filter(|value| !value.is_empty())
                    .ok_or(SecureReadAccessError::Profile)?;
                let initial = ProfileDocument {
                    version: 1,
                    origin: self.config.origin.clone(),
                    identity_path: self.config.identity_path.clone(),
                    workspace_id: self.config.workspace_id.clone(),
                    authority: self
                        .config
                        .authority
                        .clone()
                        .unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes())),
                    owner_actor_id,
                    owner_key_id,
                    required_features: self.config.required_features.clone(),
                    allow_loopback_http: self.config.allow_loopback_http,
                    current: None,
                    staged: None,
                    staged_ready: false,
                    floor: None,
                };
                write_profile(&store, &initial)?;
                initial
            }
        };
        if let Some(current) = profile.current {
            let access = self.access(&profile, current);
            let (_, checked) = access.read_checked_generation(cancel, None, false)?;
            if profile.floor.as_ref() != Some(&checked) {
                return Err(SecureReadAccessError::Profile);
            }
        }

        // A staged generation after a crash may be older than the service's
        // present head. Finish it first for recovery, then request a fresh
        // snapshot before returning latest content.
        let recovering_stage = profile.staged.is_some();
        let rounds = if recovering_stage { 2 } else { 1 };
        let mut result = None;
        for _ in 0..rounds {
            if profile.staged.is_none() {
                profile.staged = Some(1 - profile.current.unwrap_or(1));
                profile.staged_ready = false;
                write_profile(&store, &profile)?;
            }
            let slot = profile.staged.ok_or(SecureReadAccessError::Profile)?;
            let access = self.access(&profile, slot);
            if !profile.staged_ready {
                access.reset_inactive_generation(cancel)?;
                profile.staged_ready = true;
                write_profile(&store, &profile)?;
            }
            let (json, floor) =
                match access.read_checked_generation(cancel, profile.floor.as_ref(), false) {
                    Ok(checked) => checked,
                    Err(error @ SecureReadAccessError::VerificationFailed) => {
                        // A complete but invalid candidate must not be resumed forever.
                        // Keep the last verified slot and floor; the next read starts a
                        // new signed snapshot after the remote source recovers.
                        profile.staged = None;
                        profile.staged_ready = false;
                        write_profile(&store, &profile)?;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
            profile.current = Some(slot);
            profile.floor = Some(floor);
            profile.staged = None;
            profile.staged_ready = false;
            write_profile(&store, &profile)?;
            result = Some(json);
        }
        result.ok_or(SecureReadAccessError::Profile)
    }

    /// Refresh and prove the latest protected generation, then keep the
    /// profile state lock and exact replay alive through a private consumer.
    pub(crate) fn with_latest_replay<T, E, F>(
        &self,
        cancel: &CancellationToken,
        consume: F,
    ) -> Result<T, E>
    where
        E: From<SecureReadAccessError>,
        F: FnOnce(&TransportReplayedJournal) -> Result<T, E>,
    {
        self.read_latest_json_with_cancel(cancel).map_err(E::from)?;
        self.with_pinned_replay(cancel, consume)
    }

    /// Read the last protected ACTIVE generation without refreshing its
    /// pointer. Install continuation needs this authenticated pre-BEGIN source
    /// even while the newest signed journal is SEEDING.
    pub(crate) fn with_pinned_replay<T, E, F>(
        &self,
        cancel: &CancellationToken,
        consume: F,
    ) -> Result<T, E>
    where
        E: From<SecureReadAccessError>,
        F: FnOnce(&TransportReplayedJournal) -> Result<T, E>,
    {
        if cancel.is_cancelled() {
            return Err(E::from(SecureReadAccessError::Cancelled));
        }
        let store = SecureStateStore::open(&self.config.state_dir.join("read.profile"))
            .map_err(|_| E::from(SecureReadAccessError::Profile))?;
        let wire = store
            .read_exact()
            .map_err(|_| E::from(SecureReadAccessError::Profile))?
            .ok_or_else(|| E::from(SecureReadAccessError::Profile))?;
        if wire.len() > 16 * 1024 {
            return Err(E::from(SecureReadAccessError::Profile));
        }
        let saved: ProfileDocument =
            serde_json::from_slice(&wire).map_err(|_| E::from(SecureReadAccessError::Profile))?;
        if !saved.valid()
            || saved.origin != self.config.origin
            || saved.identity_path != self.config.identity_path
            || saved.workspace_id != self.config.workspace_id
            || saved.required_features != self.config.required_features
            || saved.allow_loopback_http != self.config.allow_loopback_http
            || self
                .config
                .owner_actor_id
                .as_deref()
                .is_some_and(|value| value != saved.owner_actor_id)
            || self
                .config
                .owner_key_id
                .as_deref()
                .is_some_and(|value| value != saved.owner_key_id)
            || self
                .config
                .authority
                .as_deref()
                .is_some_and(|value| value != saved.authority)
        {
            return Err(E::from(SecureReadAccessError::Profile));
        }
        let slot = saved
            .current
            .ok_or_else(|| E::from(SecureReadAccessError::Profile))?;
        let floor = saved
            .floor
            .as_ref()
            .ok_or_else(|| E::from(SecureReadAccessError::Profile))?;
        let access = self.access(&saved, slot);
        let (replayed, checked) = access
            .replay_checked_generation(cancel, Some(floor), false)
            .map_err(E::from)?;
        if &checked != floor {
            return Err(E::from(SecureReadAccessError::Profile));
        }
        consume(&replayed)
    }

    fn access(&self, profile: &ProfileDocument, slot: u8) -> SecureReadAccess {
        let state_dir = &self.config.state_dir;
        SecureReadAccess::new(SecureReadConfig {
            origin: profile.origin.clone(),
            kernel_journal_path: state_dir.join("kernel.sqlite"),
            read_state_path: state_dir.join(format!("read-{slot}.state")),
            lifecycle_path: state_dir.join("lifecycle.state"),
            identity_path: profile.identity_path.clone(),
            workspace_id: profile.workspace_id.clone(),
            authority: profile.authority.clone(),
            owner_actor_id: profile.owner_actor_id.clone(),
            owner_key_id: profile.owner_key_id.clone(),
            required_features: profile.required_features.clone(),
            allow_loopback_http: profile.allow_loopback_http,
            max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
        })
    }
}

fn write_profile(
    store: &SecureStateStore,
    profile: &ProfileDocument,
) -> Result<(), SecureReadAccessError> {
    let wire = serde_json::to_vec(profile).map_err(|_| SecureReadAccessError::Profile)?;
    store
        .write_exact(&wire)
        .map_err(|_| SecureReadAccessError::Profile)
}

fn ensure_private_directory(path: &Path) -> Result<(), SecureReadAccessError> {
    if !path.is_absolute() {
        return Err(SecureReadAccessError::Profile);
    }
    #[cfg(windows)]
    {
        crate::windows_fs::create_private_directory(path)
            .map_err(|_| SecureReadAccessError::Profile)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(SecureReadAccessError::Profile),
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(SecureReadAccessError::Profile);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_identity::KernelIdentity;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};

    #[test]
    fn invalid_generation_state_refuses_before_fetch() {
        let base = ProfileDocument {
            version: 1,
            origin: "https://example.invalid/".into(),
            identity_path: "/unread/identity".into(),
            workspace_id: "w".into(),
            authority: "a".repeat(64),
            owner_actor_id: "actor".into(),
            owner_key_id: "key".into(),
            required_features: vec![],
            allow_loopback_http: false,
            current: None,
            staged: None,
            staged_ready: false,
            floor: None,
        };
        assert!(base.valid());
        let mut changed = base.clone();
        changed.current = Some(0);
        assert!(!changed.valid());
        let mut changed = base.clone();
        changed.staged_ready = true;
        assert!(!changed.valid());
        let mut changed = base;
        changed.staged = Some(0);
        changed.current = Some(0);
        changed.floor = Some(VerifiedReadFloor {
            sequence: 1,
            head: Some("b".repeat(64)),
            policy_hash: "c".repeat(64),
        });
        assert!(!changed.valid());
    }

    #[tokio::test]
    async fn actual_service_public_profile_append_rollback_and_reopen() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "reference service did not become ready");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let fixture = &ready["public_read"];
        let identity_path = root.path().join("owner.state");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            &root.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), fixture["actor_id"].as_str().unwrap());
        let config = SecureReadProfileConfig {
            origin: origin.clone(),
            state_dir: root.path().join("profile"),
            identity_path,
            workspace_id: fixture["workspace_id"].as_str().unwrap().into(),
            owner_actor_id: Some(identity.actor_id().into()),
            owner_key_id: Some(identity.key_id().into()),
            authority: None,
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: default_replay_budget(),
        };
        let first_config = config.clone();
        let first = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(first_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let first: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(first["sequence"], 1);
        let mut reopened = config.clone();
        reopened.owner_actor_id = None;
        reopened.owner_key_id = None;
        let append = reqwest::Client::new()
            .post(format!("{origin}__test/append-public"))
            .send()
            .await
            .unwrap();
        assert_eq!(append.status(), reqwest::StatusCode::OK);
        let appended: serde_json::Value =
            serde_json::from_slice(&append.bytes().await.unwrap()).unwrap();
        assert_eq!(appended["sequence"], 2);
        let second_config = reopened.clone();
        let second = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(second_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let second: serde_json::Value = serde_json::from_str(&second).unwrap();
        assert_eq!(second["sequence"], 2);
        assert_ne!(first["head"], second["head"]);

        let delayed = reqwest::Client::new()
            .post(format!("{origin}__test/delay-next-journal"))
            .send()
            .await
            .unwrap();
        assert_eq!(delayed.status(), reqwest::StatusCode::OK);
        let cancel = CancellationToken::new();
        let cancelled_config = reopened.clone();
        let worker_cancel = cancel.clone();
        let worker = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(cancelled_config).read_latest_json_with_cancel(&worker_cancel)
        });
        let started = tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                let status = reqwest::get(format!("{origin}__test/journal-delay-status"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
                if status["started"] == true {
                    break true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(started);
        cancel.cancel();
        assert_eq!(
            worker.await.unwrap().unwrap_err(),
            SecureReadAccessError::Cancelled
        );
        let resumed_config = reopened.clone();
        let resumed = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(resumed_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let resumed: serde_json::Value = serde_json::from_str(&resumed).unwrap();
        assert_eq!(resumed["sequence"], 2);

        let stale = reqwest::Client::new()
            .post(format!("{origin}__test/serve-stale-public"))
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status(), reqwest::StatusCode::OK);
        let stale_config = reopened.clone();
        let refusal = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(stale_config).read_latest_json()
        })
        .await
        .unwrap();
        assert_eq!(
            refusal.unwrap_err(),
            SecureReadAccessError::VerificationFailed
        );
        let store = SecureStateStore::open(&config.state_dir.join("read.profile")).unwrap();
        let saved: ProfileDocument =
            serde_json::from_slice(&store.read_exact().unwrap().unwrap()).unwrap();
        assert_eq!(saved.floor.unwrap().sequence, 2);
        assert_eq!(saved.current, Some(1));
        assert_eq!(saved.staged, None);
        drop(store);
        let restore = reqwest::Client::new()
            .post(format!("{origin}__test/restore-current-public"))
            .send()
            .await
            .unwrap();
        assert_eq!(restore.status(), reqwest::StatusCode::OK);
        let recovered_config = reopened.clone();
        let recovered = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(recovered_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let recovered: serde_json::Value = serde_json::from_str(&recovered).unwrap();
        assert_eq!(recovered["sequence"], 2);
        assert_eq!(recovered["head"], second["head"]);
        let counts = reqwest::get(format!("{origin}__test/secure-counts"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let counts: serde_json::Value = serde_json::from_slice(&counts).unwrap();
        assert_eq!(counts["commits"], 2);
        assert_eq!(counts["head_sequence"], 2);
    }
}
