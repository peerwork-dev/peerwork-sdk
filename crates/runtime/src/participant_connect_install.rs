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
        let project_state = project.join(".agents/.peerwork-installation/ownership.state");
        let project_modified = std::fs::metadata(&project_state)
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(connect.install("worker", &ws, spec.clone()).unwrap(), first);
        assert_eq!(
            std::fs::metadata(&config).unwrap().modified().unwrap(),
            before
        );
        assert_eq!(
            std::fs::read(connect.directory.join("connect.state")).unwrap(),
            registry
        );
        assert_eq!(
            std::fs::metadata(&project_state)
                .unwrap()
                .modified()
                .unwrap(),
            project_modified,
            "unchanged install rewrote shared ownership"
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
    #[test]
    fn identical_preexisting_user_outputs_are_never_claimed_or_removed() {
        let root = crate::test_support::protected_test_dir();
        let project = root.path().join("project");
        files::directory(&project, false).unwrap();
        let mut connect = Connect::open(&root.path().join("local")).unwrap();
        registration(&mut connect);
        let spec = Installation {
            host: "agy".into(),
            project: project.clone(),
            executable: std::env::current_exe().unwrap(),
        };
        let ws = "W".repeat(43);
        let name = format!(
            "peerwork-{}",
            &reference(&connect.directory, &id("worker", &ws, &spec))[..16]
        );
        let agents = project.join(".agents");
        files::directory(&agents, false).unwrap();
        files::directory(&agents.join("skills"), false).unwrap();
        files::directory(&agents.join("skills/peerwork"), false).unwrap();
        let skill = agents.join("skills/peerwork/SKILL.md");
        files::replace(&skill, SKILL.as_bytes()).unwrap();
        let config = agents.join("mcp_config.json");
        let value = json!({"mcpServers":{name:entry(&connect.directory,"worker",&ws,&spec)},"user":"keep exact bytes"});
        let original = serde_json::to_vec(&value).unwrap();
        files::replace(&config, &original).unwrap();
        connect.install("worker", &ws, spec.clone()).unwrap();
        assert!(
            !connect
                .registry
                .installations
                .values()
                .next()
                .unwrap()
                .entry_owned
        );
        connect.uninstall("worker", &ws, spec).unwrap();
        assert_eq!(std::fs::read(&config).unwrap(), original);
        assert_eq!(std::fs::read(skill).unwrap(), SKILL.as_bytes());
    }
    #[test]
    fn distinct_local_identities_share_owned_skill_until_last_uninstall() {
        let root = crate::test_support::protected_test_dir();
        let project = root.path().join("project");
        files::directory(&project, false).unwrap();
        let mut first = Connect::open(&root.path().join("first")).unwrap();
        registration(&mut first);
        let mut second = Connect::open(&root.path().join("second")).unwrap();
        registration(&mut second);
        let spec = Installation {
            host: "agy".into(),
            project: project.clone(),
            executable: std::env::current_exe().unwrap(),
        };
        let ws = "W".repeat(43);
        let a = first.install("worker", &ws, spec.clone()).unwrap();
        let b = second.install("worker", &ws, spec.clone()).unwrap();
        assert_ne!(
            a["server_name"], b["server_name"],
            "two local identities must not share an MCP credential selector"
        );
        first.uninstall("worker", &ws, spec.clone()).unwrap();
        assert!(project.join(".agents/skills/peerwork/SKILL.md").is_file());
        assert!(
            json_config(&project.join(".agents/mcp_config.json")).unwrap()["mcpServers"]
                [b["server_name"].as_str().unwrap()]
            .is_object()
        );
        second.uninstall("worker", &ws, spec).unwrap();
        assert!(!project.join(".agents/skills/peerwork/SKILL.md").exists());
    }
    #[test]
    fn quoted_codex_tables_and_concurrent_editor_changes_are_preserved() {
        let desired = json!({"command":"peerwork","args":["mcp"]});
        for spelling in [
            "[\"mcp_servers\".\"peerwork-one\"]",
            "[mcp_servers.'peerwork-one']",
        ] {
            let input = format!("{spelling}\ncommand = \"user-owned\"\n");
            assert!(codex_update(
                Some(input.into_bytes()),
                "peerwork-one",
                &desired,
                None,
                false
            )
            .is_err());
        }
        let root = crate::test_support::protected_test_dir();
        let config = root.path().join("config");
        files::replace(&config, b"before").unwrap();
        let original = files::read_public_optional(&config, 100).unwrap();
        files::replace(&config, b"user changed this").unwrap();
        assert_eq!(
            files::replace_if_unchanged(&config, original.as_deref(), b"generated")
                .unwrap_err()
                .code,
            "HOST_CONFIGURATION_CONCURRENTLY_CHANGED"
        );
        assert_eq!(std::fs::read(config).unwrap(), b"user changed this");
    }
    #[test]
    fn unproven_first_publication_is_preserved_after_interrupted_install() {
        let root = crate::test_support::protected_test_dir();
        let project = root.path().join("project");
        files::directory(&project, false).unwrap();
        let mut connect = Connect::open(&root.path().join("local")).unwrap();
        registration(&mut connect);
        let spec = Installation {
            host: "agy".into(),
            project: project.clone(),
            executable: std::env::current_exe().unwrap(),
        };
        let ws = "W".repeat(43);
        connect.install("worker", &ws, spec.clone()).unwrap();
        let key = id("worker", &ws, &spec);
        let pending = connect.registry.installations.get_mut(&key).unwrap();
        pending.committed = false;
        pending.entry_owned = false;
        connect.save().unwrap();
        {
            let mut project = ProjectFiles::open(&project.join(".agents")).unwrap();
            project.ownership.skill_owned = false;
            project.ownership.skill_hash = None;
            project.ownership.pending_skill_hash = Some(sha256_hex(SKILL.as_bytes()));
            project.save().unwrap();
        }
        // These identical bytes have no confirmed publication evidence. They
        // may have been created by the user while our first write was pending.
        let config = project.join(".agents/mcp_config.json");
        let exact = std::fs::read(&config).unwrap();
        connect.install("worker", &ws, spec.clone()).unwrap();
        assert!(!connect.registry.installations[&key].entry_owned);
        connect.uninstall("worker", &ws, spec).unwrap();
        assert_eq!(std::fs::read(config).unwrap(), exact);
        assert!(project.join(".agents/skills/peerwork/SKILL.md").exists());
    }
    #[test]
    fn interrupted_upgrade_can_uninstall_its_known_old_entry() {
        for host in ["agy", "codex"] {
            let root = crate::test_support::protected_test_dir();
            let project = root.path().join("project");
            files::directory(&project, false).unwrap();
            let mut connect = Connect::open(&root.path().join("local")).unwrap();
            registration(&mut connect);
            let spec = Installation {
                host: host.into(),
                project: project.clone(),
                executable: std::env::current_exe().unwrap(),
            };
            let ws = "W".repeat(43);
            connect.install("worker", &ws, spec.clone()).unwrap();
            let key = id("worker", &ws, &spec);
            let pending = connect.registry.installations.get_mut(&key).unwrap();
            pending.previous_entry = Some(pending.entry.clone());
            pending.entry["command"] = json!("new-command-not-yet-written");
            pending.committed = false;
            connect.save().unwrap();
            assert_eq!(
                connect.uninstall("worker", &ws, spec).unwrap()["state"],
                "HOST_INTEGRATION_REMOVED"
            );
        }
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
    entry_owned: bool,
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
pub(super) fn server_name(
    directory: &Path,
    participant: &str,
    workspace: &str,
    spec: &Installation,
) -> String {
    format!(
        "peerwork-{}",
        &reference(directory, &id(participant, workspace, spec))[..16]
    )
}
fn entry(directory: &Path, participant: &str, workspace: &str, spec: &Installation) -> Value {
    json!({"command":spec.executable,"args":["agent","--local",directory,"--participant",participant,"--workspace",workspace,"mcp"]})
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectOwnership {
    references: std::collections::BTreeSet<String>,
    skill_owned: bool,
    skill_hash: Option<String>,
    pending_skill_hash: Option<String>,
}
struct ProjectFiles {
    store: SecureStateStore,
    ownership: ProjectOwnership,
}
impl ProjectFiles {
    fn open(agents: &Path) -> Result<Self> {
        let directory = agents.join(".peerwork-installation");
        files::directory(&directory, true)?;
        let store = SecureStateStore::open(&directory.join("ownership.state"))
            .map_err(|_| local("HOST_INSTALLATION_ALREADY_OWNED_OR_UNSAFE"))?;
        let ownership: ProjectOwnership = match store
            .read_exact()
            .map_err(|_| local("HOST_INSTALLATION_RECOVERY_REQUIRED"))?
        {
            Some(bytes) => serde_json::from_value(
                peerwork_core::strict_json::parse_strict_json(&bytes)
                    .map_err(|_| local("HOST_INSTALLATION_RECOVERY_REQUIRED"))?,
            )
            .map_err(|_| local("HOST_INSTALLATION_RECOVERY_REQUIRED"))?,
            None => Default::default(),
        };
        if ownership.references.len() > 64 {
            return Err(local("HOST_INSTALLATION_LIMIT"));
        }
        Ok(Self { store, ownership })
    }
    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.ownership)
            .map_err(|_| local("HOST_INSTALLATION_STATE_INVALID"))?;
        if self
            .store
            .read_exact()
            .map_err(|_| local("HOST_INSTALLATION_RECOVERY_REQUIRED"))?
            .as_ref()
            .is_some_and(|old| old.as_slice() == bytes.as_slice())
        {
            return Ok(());
        }
        self.store
            .write_exact(&bytes)
            .map_err(|_| local("HOST_INSTALLATION_WRITE_FAILED"))
    }
}
fn reference(directory: &Path, key: &str) -> String {
    sha256_hex(json!([directory, key]).to_string().as_bytes())
}
fn parse_json_config(bytes: Option<&[u8]>) -> Result<Value> {
    let value = match bytes {
        Some(bytes) => peerwork_core::strict_json::parse_strict_json(bytes)
            .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?,
        None => json!({"mcpServers":{}}),
    };
    if !value.is_object() || value.get("mcpServers").is_some_and(|v| !v.is_object()) {
        return Err(local("HOST_CONFIGURATION_INVALID"));
    }
    Ok(value)
}
#[cfg(test)]
fn json_config(path: &Path) -> Result<Value> {
    parse_json_config(files::read_public_optional(path, 256 * 1024)?.as_deref())
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
    let parsed = old
        .parse::<toml_edit::DocumentMut>()
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
        if parsed
            .get("mcp_servers")
            .and_then(|servers| servers.get(name))
            .is_some()
        {
            return Err(local("HOST_CONFIGURATION_CONFLICT"));
        }
        (old.as_str(), "", None)
    };
    let desired = if remove {
        String::new()
    } else {
        codex_block(name, wanted)
    };
    if current.is_some_and(|s| {
        s != desired
            && s != codex_block(name, wanted)
            && prior.is_none_or(|p| s != codex_block(name, p))
    }) {
        return Err(local("HOST_CONFIGURATION_CHANGED"));
    }
    let output = format!("{prefix}{desired}{suffix}");
    output
        .parse::<toml_edit::DocumentMut>()
        .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?;
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
        let reference = reference(&self.directory, &key);
        let name = server_name(&self.directory, participant, workspace, &spec);
        let wanted = entry(&self.directory, participant, workspace, &spec);
        let prior = self.registry.installations.get(&key).cloned();
        if prior.is_none() && self.registry.installations.len() >= 32 {
            return Err(local("HOST_INSTALLATION_LIMIT"));
        }
        let agents = spec.project.join(".agents");
        files::directory(&agents, false)?;
        // This project-scoped owner serializes Peerwork installations from
        // distinct identity registries and tracks shared Skill provenance.
        let mut project = ProjectFiles::open(&agents)?;
        if !project.ownership.references.contains(&reference)
            && project.ownership.references.len() >= 64
        {
            return Err(local("HOST_INSTALLATION_LIMIT"));
        }
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
                old_config.clone(),
                &name,
                &wanted,
                prior
                    .as_ref()
                    .filter(|p| p.entry_owned)
                    .map(|p| p.previous_entry.as_ref().unwrap_or(&p.entry)),
                false,
            )?
        } else {
            let mut value = parse_json_config(old_config.as_deref())?;
            if value.get("mcpServers").is_none() {
                value["mcpServers"] = json!({});
            }
            let existing = &value["mcpServers"][&name];
            if !existing.is_null()
                && existing != &wanted
                && prior.as_ref().is_none_or(|p| {
                    !p.entry_owned
                        || (existing != &p.entry && p.previous_entry.as_ref() != Some(existing))
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
        let entry_owned = prior.as_ref().is_some_and(|p| p.entry_owned);
        // A plan to publish is not proof of publication. On a lost pre-write
        // attempt, an identical file encountered later remains user-owned.
        let skills = agents.join("skills");
        files::directory(&skills, false)?;
        let skill_dir = skills.join("peerwork");
        files::directory(&skill_dir, false)?;
        let skill = skill_dir.join("SKILL.md");
        let existing_skill = files::read_public_optional(&skill, 65536)?;
        let hash = sha256_hex(SKILL.as_bytes());
        if existing_skill.as_ref().is_some_and(|v| {
            v.as_slice() != SKILL.as_bytes()
                && !(project.ownership.skill_owned
                    && (project.ownership.skill_hash.as_ref() == Some(&sha256_hex(v))
                        || project.ownership.pending_skill_hash.as_ref() == Some(&sha256_hex(v))))
        }) {
            return Err(local("HOST_SKILL_CHANGED"));
        }
        if existing_skill.is_none() {
            project.ownership.skill_owned = false;
            project.ownership.skill_hash = None;
        }
        // Identical preexisting files remain user-owned. A hash match by itself
        // does not establish that this installer created or may remove them.
        project.ownership.references.insert(reference);
        if existing_skill.as_deref() != Some(SKILL.as_bytes())
            || (project.ownership.skill_owned
                && project.ownership.skill_hash.as_ref() != Some(&hash))
        {
            project.ownership.pending_skill_hash = Some(hash.clone());
        }
        project.save()?;
        let record = Installed {
            participant: participant.into(),
            workspace_id: workspace.into(),
            spec: spec.clone(),
            name: name.clone(),
            entry: wanted,
            skill_hash: hash,
            committed: false,
            entry_owned,
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
        // Save the intended entries before publication. Deletion authority is
        // recorded only after our own successful write; ambiguous first-write
        // crashes conservatively retain files rather than claiming ownership.
        if prior.as_ref().is_none_or(|p| {
            p.entry != record.entry
                || p.skill_hash != record.skill_hash
                || p.entry_owned != record.entry_owned
                || !p.committed
        }) {
            self.registry.installations.insert(key.clone(), record);
            self.save()?;
        }
        if let Some(bytes) = new_config {
            files::replace_if_unchanged(&config, old_config.as_deref(), &bytes)?;
            self.registry
                .installations
                .get_mut(&key)
                .unwrap()
                .entry_owned = true;
            self.save()?;
        }
        if existing_skill.as_deref() != Some(SKILL.as_bytes()) {
            files::replace_if_unchanged(&skill, existing_skill.as_deref(), SKILL.as_bytes())?;
            project.ownership.skill_owned = true;
        }
        if let Some(hash) = project.ownership.pending_skill_hash.take() {
            if project.ownership.skill_owned {
                project.ownership.skill_hash = Some(hash);
            }
            project.save()?;
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
        let mut project = ProjectFiles::open(&spec.project.join(".agents"))?;
        let old_config = files::read_public_optional(&config, 256 * 1024)?;
        let new_config = if !owned.entry_owned {
            None
        } else if spec.host == "codex" {
            codex_update(
                old_config.clone(),
                &owned.name,
                &owned.entry,
                if owned.committed {
                    Some(&owned.entry)
                } else {
                    owned.previous_entry.as_ref().or(Some(&owned.entry))
                },
                true,
            )?
        } else {
            let mut value = parse_json_config(old_config.as_deref())?;
            if value["mcpServers"][&owned.name].is_null() {
                None
            } else {
                if value["mcpServers"][&owned.name] != owned.entry
                    && (owned.committed
                        || owned.previous_entry.as_ref() != Some(&value["mcpServers"][&owned.name]))
                {
                    return Err(local("HOST_CONFIGURATION_CHANGED"));
                }
                value["mcpServers"]
                    .as_object_mut()
                    .ok_or_else(|| local("HOST_CONFIGURATION_INVALID"))?
                    .remove(&owned.name);
                Some(
                    serde_json::to_vec_pretty(&value)
                        .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?,
                )
            }
        };
        let own_reference = reference(&self.directory, &key);
        let shared = project
            .ownership
            .references
            .iter()
            .any(|r| r != &own_reference);
        let skill = spec.project.join(".agents/skills/peerwork/SKILL.md");
        let existing_skill = files::read_public_optional(&skill, 65536)?;
        let remove_skill = !shared
            && project.ownership.skill_owned
            && existing_skill.as_ref().is_some_and(|bytes| {
                let hash = sha256_hex(bytes);
                project.ownership.skill_hash.as_ref() == Some(&hash)
                    || project.ownership.pending_skill_hash.as_ref() == Some(&hash)
            });
        if let Some(bytes) = new_config {
            files::replace_if_unchanged(&config, old_config.as_deref(), &bytes)?;
        }
        if remove_skill {
            files::remove_if_unchanged(&skill, existing_skill.as_deref().unwrap())?;
        }
        let skill_retained = existing_skill.is_some() && !remove_skill;
        project.ownership.references.remove(&own_reference);
        if remove_skill {
            project.ownership.skill_owned = false;
            project.ownership.skill_hash = None;
            project.ownership.pending_skill_hash = None;
        }
        project.save()?;
        self.registry.installations.remove(&key);
        self.save()?;
        Ok(
            json!({"state":"HOST_INTEGRATION_REMOVED","identity_and_recovery_retained":true,"remote_grants_changed":false,"skill_retained":skill_retained}),
        )
    }
}
