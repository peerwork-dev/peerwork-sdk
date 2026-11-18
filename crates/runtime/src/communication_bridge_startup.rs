//! Relaunch an explicitly started, same-user Codex bridge from its original files.
use super::{digest_value, private_json, BridgeConfig, R};
use crate::{runtime_startup::Launcher, secure_state::SecureStateStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};

#[derive(Serialize, Deserialize)]
pub(super) struct Startup {
    path: PathBuf,
    config_digest: String,
    working_directory: PathBuf,
    launcher: Launcher,
    enabled: bool,
    retry_after_ms: i64,
}

fn lock(directory: &Path) -> R<SecureStateStore> {
    SecureStateStore::open(&directory.join("bridge-startup.state"))
        .map_err(|_| "BRIDGE_STARTUP_LOCK_UNAVAILABLE")
}

impl Startup {
    fn read(state: &SecureStateStore) -> R<Option<Self>> {
        state.read_exact().map_err(|_| "BRIDGE_STARTUP_INVALID")?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| "BRIDGE_STARTUP_INVALID"))
            .transpose()
    }

    fn save(&self, state: &SecureStateStore) -> R<()> {
        let bytes = serde_json::to_vec(self).map_err(|_| "BRIDGE_STARTUP_INVALID")?;
        state.write_exact(&bytes).map_err(|_| "BRIDGE_STARTUP_INVALID")
    }

    pub(super) fn open(config: &BridgeConfig, path: &Path, digest: String, recovery: bool)
        -> R<(SecureStateStore, Self)>
    {
        let state = lock(&config.state_directory)?;
        let path = std::path::absolute(path).map_err(|_| "BRIDGE_CONFIG_INVALID")?;
        let launcher = Launcher::capture(
            std::env::current_exe().map_err(|_| "BRIDGE_STARTUP_INVALID")?,
        ).map_err(|_| "BRIDGE_STARTUP_INVALID")?;
        let record = if recovery {
            let record = Self::read(&state)?.ok_or("BRIDGE_STARTUP_NOT_CONFIGURED")?;
            if !record.enabled || record.path != path || record.config_digest != digest
                || record.launcher != launcher
            {
                return Err("BRIDGE_STARTUP_CHANGED");
            }
            record
        } else {
            Self {
                path, config_digest: digest, launcher, enabled: true, retry_after_ms: 0,
                working_directory: std::env::current_dir().map_err(|_| "BRIDGE_STARTUP_INVALID")?,
            }
        };
        Ok((state, record))
    }

    pub(super) fn ready(&self, state: &SecureStateStore) -> R<()> {
        self.save(state)
    }

    pub(super) fn stop(&mut self, state: &SecureStateStore) -> R<()> {
        self.enabled = false;
        self.save(state)
    }
}

pub(crate) fn recover(adapter: &Value, executor: &tokio::runtime::Handle) -> R<Option<tokio::process::Child>> {
    let key = adapter["token_file"].as_str().ok_or("BRIDGE_STARTUP_NOT_CONFIGURED")?;
    let directory = Path::new(key).parent().ok_or("BRIDGE_STARTUP_NOT_CONFIGURED")?;
    if !directory.join("bridge-startup.state").is_file() {
        return Err("BRIDGE_STARTUP_NOT_CONFIGURED");
    }
    let state = lock(directory)?;
    let mut record = Startup::read(&state)?.ok_or("BRIDGE_STARTUP_NOT_CONFIGURED")?;
    let now = crate::participant_store::now();
    if !record.enabled || record.retry_after_ms > now {
        return Ok(None);
    }
    let descriptor = private_json(&directory.join("bridge-endpoint.json"), 131072)?;
    if !descriptor["adapters"].as_array().is_some_and(|items| {
        items.iter().any(|entry| entry["adapter"] == *adapter)
    }) {
        return Err("BRIDGE_STARTUP_CHANGED");
    }
    let value = private_json(&record.path, 65536)?;
    if digest_value(&value) != record.config_digest || value["host"]["kind"] != "codex"
        || value["state_directory"].as_str().map(Path::new) != Some(directory)
    {
        return Err("BRIDGE_STARTUP_CHANGED");
    }
    record.launcher.verify().map_err(|_| "BRIDGE_STARTUP_CHANGED")?;
    record.retry_after_ms = now.saturating_add(15_000);
    record.save(&state)?;

    drop(state);
    // The persisted cooldown prevents competing launches before the child locks.
    // Tokio reaps the process even after the handle is dropped.
    let mut command = tokio::process::Command::new(&record.launcher.executable);
    command.args(["bridge", "recover-original"]).arg(&record.path)
        .current_dir(&record.working_directory)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let _runtime = executor.enter();
    command.spawn().map(Some).map_err(|_| "BRIDGE_STARTUP_FAILED")
}
