//! Owned project MCP/Skill integration, selected only by the local host owner.
//! No tool argument can choose arbitrary commands, user homes or config paths.
use super::*;
use crate::onboarding_files as files;
const SKILL: &str = include_str!("../../../skills/peerwork/SKILL.md");
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub host: String,
    pub project: PathBuf,
    pub executable: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn registration(connect: &mut Connect) {
        connect.registry.participants.insert(
            "worker".into(),
            Registration {
                origin: "https://example.invalid/".into(),
                actor_id: "A".repeat(43),
                endpoint_path: connect.directory.join("selected.json"),
            },
        );
        connect.save().unwrap();
    }
    #[test]
    fn owned_project_install_preserves_other_servers_is_idempotent_and_uninstalls_only_owned_outputs(
    ) {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path().join("project");
        files::directory(&project, false).unwrap();
        let agents = project.join(".agents");
        files::directory(&agents, false).unwrap();
        let config = agents.join("mcp_config.json");
        let other =
            json!({"mcpServers":{"unrelated":{"command":"other","args":[]}},"extra":{"keep":true}});
        files::replace(&config, &serde_json::to_vec(&other).unwrap()).unwrap();
        let mut connect = Connect::open(&project.join("private-peerwork")).unwrap();
        registration(&mut connect);
        let spec = Installation {
            host: "agy".into(),
            project: project.clone(),
            executable: std::env::current_exe().unwrap(),
        };
        let ws = "W".repeat(43);
        let first = connect.install("worker", &ws, spec.clone()).unwrap();
        let before = std::fs::metadata(&config).unwrap().modified().unwrap();
        let registry = std::fs::read(connect.directory.join("connect.state")).unwrap();
        assert_eq!(connect.install("worker", &ws, spec.clone()).unwrap(), first);
        assert_eq!(
            std::fs::metadata(&config).unwrap().modified().unwrap(),
            before
        );
        assert_eq!(
            std::fs::read(connect.directory.join("connect.state")).unwrap(),
            registry
        );
        let value = json_config(&config).unwrap();
        assert_eq!(
            value["mcpServers"]["unrelated"],
            other["mcpServers"]["unrelated"]
        );
        assert_eq!(value["extra"], other["extra"]);
        let name = first["server_name"].as_str().unwrap();
        assert_eq!(value["mcpServers"][name]["args"][4], "worker");
        let mut changed = value.clone();
        changed["mcpServers"][name]["args"] = json!(["user-changed"]);
        files::replace(&config, &serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(
            connect
                .uninstall("worker", &ws, spec.clone())
                .unwrap_err()
                .code,
            "HOST_CONFIGURATION_CHANGED"
        );
        assert_eq!(json_config(&config).unwrap(), changed);
        files::replace(&config, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            connect.uninstall("worker", &ws, spec).unwrap()["state"],
            "HOST_INTEGRATION_REMOVED"
        );
        assert_eq!(json_config(&config).unwrap(), other);
        assert!(!project.join(".agents/skills/peerwork/SKILL.md").exists());
    }
    #[test]
    fn codex_owned_blocks_preserve_unrelated_toml_and_resume_interrupted_upgrade() {
        let old = b"[mcp_servers.unrelated]\ncommand = \"other\"\nargs = []\n".to_vec();
        let a = json!({"command":"/path with spaces/peerwork","args":["agent","--local","/private","mcp"]});
        let b = json!({"command":"/new/peerwork","args":["agent","--local","/private","mcp"]});
        let installed = codex_update(Some(old.clone()), "peerwork-one", &a, None, false)
            .unwrap()
            .unwrap();
        assert!(
            codex_update(Some(installed.clone()), "peerwork-one", &a, Some(&a), false)
                .unwrap()
                .is_none()
        );
        let updated = codex_update(Some(installed), "peerwork-one", &b, Some(&a), false)
            .unwrap()
            .unwrap();
        assert!(String::from_utf8(updated.clone())
            .unwrap()
            .starts_with(std::str::from_utf8(&old).unwrap()));
        let removed = codex_update(Some(updated), "peerwork-one", &b, Some(&b), true)
            .unwrap()
            .unwrap();
        assert_eq!(removed, old);
        let user_owned = b"[mcp_servers.peerwork-one]\ncommand = \"other\"\n".to_vec();
        assert!(codex_update(Some(user_owned), "peerwork-one", &a, None, false).is_err());
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installed {
    participant: String,
    workspace_id: String,
    spec: Installation,
    name: String,
    entry: Value,
    skill_hash: String,
    committed: bool,
    #[serde(default)]
    previous_entry: Option<Value>,
    #[serde(default)]
    previous_skill_hash: Option<String>,
}
fn id(participant: &str, workspace: &str, spec: &Installation) -> String {
    sha256_hex(
        json!([participant, workspace, spec.host, spec.project])
            .to_string()
            .as_bytes(),
    )
}
fn entry(directory: &Path, participant: &str, workspace: &str, spec: &Installation) -> Value {
    json!({"command":spec.executable,"args":["agent","--local",directory,"--participant",participant,"--workspace",workspace,"mcp"]})
}
fn json_config(path: &Path) -> Result<Value> {
    match files::read_public_optional(path, 256 * 1024)? {
        Some(bytes) => {
            let value = peerwork_core::strict_json::parse_strict_json(&bytes)
                .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?;
            if !value.is_object() || value.get("mcpServers").is_some_and(|v| !v.is_object()) {
                return Err(local("HOST_CONFIGURATION_INVALID"));
            }
            Ok(value)
        }
        None => Ok(json!({"mcpServers":{}})),
    }
}
fn codex_block(name: &str, entry: &Value) -> String {
    // JSON string escaping is also a valid TOML basic-string spelling for these
    // paths/arguments. No shell evaluates any generated string.
    format!("\n# peerwork-owned {name} begin\n[mcp_servers.{name}]\ncommand = {}\nargs = {}\n# peerwork-owned {name} end\n",
        entry["command"],entry["args"])
}
fn codex_update(
    bytes: Option<Vec<u8>>,
    name: &str,
    wanted: &Value,
    prior: Option<&Value>,
    remove: bool,
) -> Result<Option<Vec<u8>>> {
    let old = String::from_utf8(bytes.unwrap_or_default())
        .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?;
    let begin = format!("\n# peerwork-owned {name} begin\n");
    let end = format!("# peerwork-owned {name} end\n");
    let (prefix, suffix, current) = if let Some(start) = old.find(&begin) {
        let tail = &old[start..];
        let stop = tail
            .find(&end)
            .ok_or_else(|| local("HOST_CONFIGURATION_CONFLICT"))?
            + end.len();
        if tail[stop..].contains(&begin) {
            return Err(local("HOST_CONFIGURATION_CONFLICT"));
        }
        (&old[..start], &tail[stop..], Some(&tail[..stop]))
    } else {
        if old.lines().any(|line| {
            line.trim().starts_with(&format!("[mcp_servers.{name}"))
                || line.contains(&format!("\"{name}\""))
        }) {
            return Err(local("HOST_CONFIGURATION_CONFLICT"));
        }
        (old.as_str(), "", None)
    };
    let desired = if remove {
        String::new()
    } else {
        codex_block(name, wanted)
    };
    if current.is_some_and(|s| s != desired && prior.is_none_or(|p| s != codex_block(name, p))) {
        return Err(local("HOST_CONFIGURATION_CHANGED"));
    }
    let output = format!("{prefix}{desired}{suffix}");
    Ok((output != old).then(|| output.into_bytes()))
}
impl Connect {
    pub fn install(
        &mut self,
        participant: &str,
        workspace: &str,
        spec: Installation,
    ) -> Result<Value> {
        self.require_writer()?;
        if !self.registry.participants.contains_key(participant)
            || !token(workspace)
            || !["codex", "agy"].contains(&spec.host.as_str())
            || !spec.executable.is_absolute()
            || !std::fs::metadata(&spec.executable).is_ok_and(|m| m.is_file())
        {
            return Err(local("HOST_INSTALLATION_SELECTION_INVALID"));
        }
        files::check_directory(&spec.project, false)?;
        let key = id(participant, workspace, &spec);
        let name = format!("peerwork-{}", &key[..16]);
        let wanted = entry(&self.directory, participant, workspace, &spec);
        let prior = self.registry.installations.get(&key).cloned();
        if prior.is_none() && self.registry.installations.len() >= 32 {
            return Err(local("HOST_INSTALLATION_LIMIT"));
        }
        let agents = spec.project.join(".agents");
        files::directory(&agents, false)?;
        let config = if spec.host == "codex" {
            let dir = spec.project.join(".codex");
            files::directory(&dir, false)?;
            dir.join("config.toml")
        } else {
            agents.join("mcp_config.json")
        };
        let old_config = files::read_public_optional(&config, 256 * 1024)?;
        let new_config = if spec.host == "codex" {
            codex_update(
                old_config,
                &name,
                &wanted,
                prior
                    .as_ref()
                    .map(|p| p.previous_entry.as_ref().unwrap_or(&p.entry)),
                false,
            )?
        } else {
            let mut value = json_config(&config)?;
            if value.get("mcpServers").is_none() {
                value["mcpServers"] = json!({});
            }
            let existing = &value["mcpServers"][&name];
            if !existing.is_null()
                && existing != &wanted
                && prior.as_ref().is_none_or(|p| {
                    existing != &p.entry && p.previous_entry.as_ref() != Some(existing)
                })
            {
                return Err(local("HOST_CONFIGURATION_CHANGED"));
            }
            if existing == &wanted {
                None
            } else {
                value["mcpServers"][&name] = wanted.clone();
                Some(
                    serde_json::to_vec_pretty(&value)
                        .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?,
                )
            }
        };
        let skills = agents.join("skills");
        files::directory(&skills, false)?;
        let skill_dir = skills.join("peerwork");
        files::directory(&skill_dir, false)?;
        let skill = skill_dir.join("SKILL.md");
        let existing_skill = files::read_public_optional(&skill, 65536)?;
        let hash = sha256_hex(SKILL.as_bytes());
        if existing_skill.as_ref().is_some_and(|v| {
            v.as_slice() != SKILL.as_bytes()
                && prior.as_ref().is_none_or(|p| {
                    sha256_hex(v) != p.skill_hash && Some(sha256_hex(v)) != p.previous_skill_hash
                })
        }) {
            return Err(local("HOST_SKILL_CHANGED"));
        }
        let record = Installed {
            participant: participant.into(),
            workspace_id: workspace.into(),
            spec: spec.clone(),
            name: name.clone(),
            entry: wanted,
            skill_hash: hash,
            committed: false,
            previous_entry: prior.as_ref().map(|p| {
                if p.committed {
                    p.entry.clone()
                } else {
                    p.previous_entry.clone().unwrap_or_else(|| p.entry.clone())
                }
            }),
            previous_skill_hash: prior.as_ref().map(|p| {
                if p.committed {
                    p.skill_hash.clone()
                } else {
                    p.previous_skill_hash
                        .clone()
                        .unwrap_or_else(|| p.skill_hash.clone())
                }
            }),
        };
        // Keep ownership before touching either host output, so an interrupted
        // install can reconcile exactly these entries instead of overwriting.
        if prior.as_ref().is_none_or(|p| {
            p.entry != record.entry || p.skill_hash != record.skill_hash || !p.committed
        }) {
            self.registry.installations.insert(key.clone(), record);
            self.save()?;
        }
        if let Some(bytes) = new_config {
            files::replace(&config, &bytes)?;
        }
        if existing_skill.as_deref() != Some(SKILL.as_bytes()) {
            files::replace(&skill, SKILL.as_bytes())?;
        }
        if !self.registry.installations[&key].committed {
            self.registry.installations.get_mut(&key).unwrap().committed = true;
            self.save()?;
        }
        Ok(
            json!({"state":"HOST_INTEGRATION_INSTALLED","host":spec.host,"server_name":name,"participant":participant,"workspace_id":workspace,
            "mcp_configuration":config,"skill":skill,"current_session_tools":"NOT_ATTESTED","host_delivery":"NOT_BOUND",
            "next_action":"REFRESH_HOST_AND_CALL_PEERWORK_CONTEXT","identity_files_copied":false}),
        )
    }
    pub fn uninstall(
        &mut self,
        participant: &str,
        workspace: &str,
        spec: Installation,
    ) -> Result<Value> {
        self.require_writer()?;
        let key = id(participant, workspace, &spec);
        let Some(owned) = self.registry.installations.get(&key).cloned() else {
            return Ok(json!({"state":"HOST_INTEGRATION_ABSENT"}));
        };
        files::check_directory(&spec.project, false)?;
        let config = spec.project.join(if spec.host == "codex" {
            ".codex/config.toml"
        } else {
            ".agents/mcp_config.json"
        });
        if spec.host == "codex" {
            if let Some(bytes) = codex_update(
                files::read_public_optional(&config, 256 * 1024)?,
                &owned.name,
                &owned.entry,
                Some(&owned.entry),
                true,
            )? {
                files::replace(&config, &bytes)?;
            }
        } else {
            let mut value = json_config(&config)?;
            if !value["mcpServers"][&owned.name].is_null() {
                if value["mcpServers"][&owned.name] != owned.entry {
                    return Err(local("HOST_CONFIGURATION_CHANGED"));
                }
                value["mcpServers"]
                    .as_object_mut()
                    .ok_or_else(|| local("HOST_CONFIGURATION_INVALID"))?
                    .remove(&owned.name);
                files::replace(
                    &config,
                    &serde_json::to_vec_pretty(&value)
                        .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?,
                )?;
            }
        }
        let skill = spec.project.join(".agents/skills/peerwork/SKILL.md");
        let shared = self
            .registry
            .installations
            .iter()
            .any(|(k, p)| k != &key && p.spec.project == spec.project);
        let mut skill_retained = shared;
        if !shared {
            if let Some(bytes) = files::read_public_optional(&skill, 65536)? {
                if sha256_hex(&bytes) == owned.skill_hash {
                    std::fs::remove_file(&skill).map_err(|_| local("HOST_SKILL_REMOVE_FAILED"))?;
                } else {
                    skill_retained = true;
                }
            }
        }
        self.registry.installations.remove(&key);
        self.save()?;
        Ok(
            json!({"state":"HOST_INTEGRATION_REMOVED","identity_and_recovery_retained":true,"remote_grants_changed":false,"skill_retained":skill_retained}),
        )
    }
}
