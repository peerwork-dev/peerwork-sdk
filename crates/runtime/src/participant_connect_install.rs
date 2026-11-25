//! Owned project MCP/Skill integration, selected only by the local host owner.
//! No tool argument can choose arbitrary commands, user homes or config paths.
use super::*;
use crate::onboarding_files as files;
const SKILL: &str = include_str!("../../../skills/peerwork/SKILL.md");

pub(super) fn persistent_executable(executable: &Path) -> Result<PathBuf> {
    let path=std::fs::canonicalize(executable).map_err(|_|local("HOST_INSTALLATION_SELECTION_INVALID"))?;
    let temporary=std::env::temp_dir();
    if path.starts_with(&temporary) || cfg!(unix) && (path.starts_with("/tmp") || path.starts_with("/var/tmp")) {
        let mut error=local("TEMPORARY_EXECUTABLE_REQUIRES_PERSISTENT_INSTALL");
        error.details=Some(json!({"field":"executable","next_action":"INSTALL_VERIFIED_BINARY_AT_PERSISTENT_PATH_THEN_REPEAT_CONNECT",
            "existing_installation_preserved":true}));
        return Err(error);
    }
    Ok(path)
}
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
    #[test]
    fn temporary_executable_is_rejected_before_installation_state_changes() {
        let root=crate::test_support::protected_test_dir();
        let project=root.path().join("project");files::directory(&project,false).unwrap();
        let mut connect=Connect::open(&root.path().join("local")).unwrap();registration(&mut connect);
        let executable=root.path().join("extracted-peerwork");std::fs::write(&executable,b"synthetic executable").unwrap();
        let before=std::fs::read(connect.directory.join("connect.state")).unwrap();
        let error=connect.install("worker",&"W".repeat(43),Installation{host:"opencode".into(),project:project.clone(),executable}).unwrap_err();
        assert_eq!(error.code,"TEMPORARY_EXECUTABLE_REQUIRES_PERSISTENT_INSTALL");
        assert_eq!(error.details.unwrap()["field"],"executable");
        assert_eq!(std::fs::read(connect.directory.join("connect.state")).unwrap(),before);
        assert!(!project.join(".opencode").exists());
    }
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
    fn opencode_v2_owned_install_discovery_and_uninstall_keep_original_identity_and_other_servers() {
        let root=crate::test_support::protected_test_dir();let project=root.path().join("project with spaces");files::directory(&project,false).unwrap();
        let dir=project.join(".opencode");files::directory(&dir,false).unwrap();
        let config=dir.join("opencode.json");
        let original=json!({"mcp":{"servers":{"unrelated":{"type":"local","command":["preserve"]}},"timeout":{"startup":45000}},"model":"preserve/model"});
        files::replace(&config,&serde_json::to_vec(&original).unwrap()).unwrap();
        let mut c=Connect::open(&root.path().join("local")).unwrap();registration(&mut c);
        let identity=serde_json::to_value(&c.registry.participants).unwrap();let ws="W".repeat(43);
        let spec=Installation{host:"opencode".into(),project:project.clone(),executable:std::env::current_exe().unwrap()};
        let installed=c.install("worker",&ws,spec.clone()).unwrap();let name=installed["server_name"].as_str().unwrap();
        let value=json_config(&config).unwrap();let entry=&value["mcp"]["servers"][name];
        assert_eq!(entry["type"],"local");assert_eq!(entry["protocol"],"2026-07-28");assert_eq!(entry["command"].as_array().unwrap().len(),9);
        assert!(entry.get("enabled").is_none());assert!(entry.get("args").is_none());assert!(value.get("mcpServers").is_none());
        assert_eq!(value["mcp"]["servers"]["unrelated"],original["mcp"]["servers"]["unrelated"]);
        assert_eq!(std::fs::read(dir.join("skills/peerwork/SKILL.md")).unwrap(),SKILL.as_bytes());
        let before=std::fs::read(&config).unwrap();let at=std::fs::metadata(&config).unwrap().modified().unwrap();
        assert_eq!(c.install("worker",&ws,spec.clone()).unwrap(),installed);assert_eq!(std::fs::metadata(&config).unwrap().modified().unwrap(),at);
        assert_eq!(std::fs::read(&config).unwrap(),before);
        let choices=super::super::discovery::project_bindings(&project,Some(&ws)).unwrap();
        assert_eq!(choices.len(),1);
        assert_eq!(serde_json::to_value(&c.registry.participants).unwrap(),identity);
        c.uninstall("worker",&ws,spec).unwrap();assert_eq!(json_config(&config).unwrap(),original);
        assert!(!dir.join("skills/peerwork/SKILL.md").exists());
    }
    #[test]
    fn opencode_v1_config_is_rejected_and_user_edited_v2_entry_is_named() {
        let root=crate::test_support::protected_test_dir();let project=root.path().join("project");files::directory(&project,false).unwrap();
        let dir=project.join(".opencode");files::directory(&dir,false).unwrap();let config=dir.join("opencode.json");
        let v1=json!({"mcp":{"existing":{"type":"local","command":["keep"],"enabled":true}}});
        files::replace(&config,&serde_json::to_vec(&v1).unwrap()).unwrap();
        let mut c=Connect::open(&root.path().join("local")).unwrap();registration(&mut c);let ws="W".repeat(43);
        let spec=Installation{host:"opencode".into(),project:project.clone(),executable:std::env::current_exe().unwrap()};
        assert_eq!(c.install("worker",&ws,spec.clone()).unwrap_err().code,"HOST_CONFIGURATION_REQUIRES_OPENCODE_V2_MCP_SERVERS");
        assert_eq!(json_config(&config).unwrap(),v1);
        files::replace(&config,b"{}").unwrap();let result=c.install("worker",&ws,spec.clone()).unwrap();let name=result["server_name"].as_str().unwrap();
        let mut value=json_config(&config).unwrap();value["mcp"]["servers"][name]["command"]=json!(["user-edited"]);
        files::replace(&config,&serde_json::to_vec(&value).unwrap()).unwrap();
        let error=c.uninstall("worker",&ws,spec).unwrap_err();assert_eq!(error.code,"HOST_CONFIGURATION_CHANGED");
        assert_eq!(error.details.unwrap()["field"],format!("mcp.servers.{name}"));assert_eq!(json_config(&config).unwrap(),value);
    }
    #[test]
    fn claude_installs_native_mcp_and_skill_without_replacing_other_hosts_or_identity() {
        let root=crate::test_support::protected_test_dir();let project=root.path().join("project");files::directory(&project,false).unwrap();
        let original=json!({"mcpServers":{"unrelated":{"command":"preserve","args":["original"]}},"extra":{"keep":true}});
        files::replace(&project.join(".mcp.json"),&serde_json::to_vec(&original).unwrap()).unwrap();
        let mut c=Connect::open(&root.path().join("local")).unwrap();registration(&mut c);
        let identity=serde_json::to_value(&c.registry.participants).unwrap();
        let ws="W".repeat(43);let claude=Installation{host:"claude".into(),project:project.clone(),executable:std::env::current_exe().unwrap()};
        let agy=Installation{host:"agy".into(),..claude.clone()};
        #[cfg(target_os = "linux")]
        let settings = {
            files::directory(&project.join(".claude"), false).unwrap();
            let path = project.join(".claude/settings.local.json");
            let original = json!({"permissions":{"allow":["Read"]},"hooks":{
                "SessionStart":[{"hooks":[{"type":"command","command":"echo user-hook"}]}]}});
            files::replace(&path, &serde_json::to_vec(&original).unwrap()).unwrap();
            (path, original)
        };
        c.install("worker",&ws,agy.clone()).unwrap();
        let installed=c.install("worker",&ws,claude.clone()).unwrap();
        assert_eq!(installed["channel"]["state"],"ACTIVATION_REQUIRED");
        assert_eq!(installed["channel"]["host_acceptance"],"NOT_ATTESTED");
        let name=installed["server_name"].as_str().unwrap();let config=json_config(&project.join(".mcp.json")).unwrap();
        assert_eq!(config["mcpServers"]["unrelated"],original["mcpServers"]["unrelated"]);
        assert_eq!(config["mcpServers"][name]["type"],"stdio");
        assert_eq!(config["mcpServers"][name]["args"][8],"--claude-channel");
        assert_eq!(std::fs::read(project.join(".claude/skills/peerwork/SKILL.md")).unwrap(),SKILL.as_bytes());
        #[cfg(target_os = "linux")]
        let installed_settings = {
            let bytes = std::fs::read(&settings.0).unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["permissions"], settings.1["permissions"]);
            assert_eq!(value["hooks"]["SessionStart"][0], settings.1["hooks"]["SessionStart"][0]);
            assert!(value["hooks"]["SessionStart"][1]["hooks"][0]["command"].as_str().unwrap()
                .ends_with(&format!(" agent claude-session-start {name}")));
            assert!(value["hooks"]["SessionEnd"][0]["hooks"][0]["command"].as_str().unwrap()
                .ends_with(&format!(" agent claude-session-end {name}")));
            bytes
        };
        let before=std::fs::metadata(project.join(".mcp.json")).unwrap().modified().unwrap();
        assert_eq!(c.install("worker",&ws,claude.clone()).unwrap(),installed);
        assert_eq!(std::fs::metadata(project.join(".mcp.json")).unwrap().modified().unwrap(),before);
        assert_eq!(serde_json::to_value(&c.registry.participants).unwrap(),identity);
        let discovered=super::super::discovery::project_bindings(&project,Some(&ws)).unwrap();
        assert_eq!(discovered.len(),1,"same identity is one discovery choice across hosts");
        c.uninstall("worker",&ws,agy).unwrap();
        assert!(project.join(".claude/skills/peerwork/SKILL.md").is_file());
        #[cfg(target_os = "linux")]
        assert_eq!(std::fs::read(&settings.0).unwrap(), installed_settings);
        c.uninstall("worker",&ws,claude).unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(&settings.0).unwrap()).unwrap(), settings.1);
        assert_eq!(json_config(&project.join(".mcp.json")).unwrap(),original);
        assert!(!project.join(".claude/skills/peerwork/SKILL.md").exists());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn claude_uninstall_preserves_a_preexisting_identical_hook() {
        let root = crate::test_support::protected_test_dir();
        let project = root.path().join("project");
        files::directory(&project, false).unwrap();
        files::directory(&project.join(".claude"), false).unwrap();
        let mut connect = Connect::open(&root.path().join("local")).unwrap();
        registration(&mut connect);
        let workspace = "W".repeat(43);
        let spec = Installation { host: "claude".into(), project: project.clone(),
            executable: persistent_executable(&std::env::current_exe().unwrap()).unwrap() };
        let server = server_name(&connect.directory, "worker", &workspace, &spec);
        let plan = claude_settings_update(None, &server, Some(&spec.executable), None, None).unwrap();
        let both: Value = serde_json::from_slice(&plan.replacement.unwrap()).unwrap();
        let original = json!({"hooks":{"SessionStart":both["hooks"]["SessionStart"]}});
        let settings = project.join(".claude/settings.local.json");
        files::replace(&settings, &serde_json::to_vec(&original).unwrap()).unwrap();

        connect.install("worker", &workspace, spec.clone()).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(&settings).unwrap()).unwrap(), both);
        let replacement = root.path().join("another-peerwork");
        let saved = connect.registry.installations.values().next().unwrap();
        let reference = reference(&connect.directory, &id("worker", &workspace, &spec));
        let ownership = ClaudeHookOwnership::open(&spec.project).unwrap();
        let error = claude_settings_update(Some(&std::fs::read(&settings).unwrap()), &server, Some(&replacement),
            Some(saved), ownership.claims.get(&reference)).err().unwrap();
        assert_eq!(error.code, "CLAUDE_CHANNEL_SETTINGS_CHANGED");
        assert_eq!(error.details.unwrap()["event"], "SessionStart");
        // Simulate an uninstall that removed its own hook but stopped before
        // committing the local installation removal.
        let mut ownership = ownership;
        ownership.save(&reference, Some([None, None])).unwrap();
        files::replace(&settings, &serde_json::to_vec(&original).unwrap()).unwrap();
        drop(ownership);
        assert!(connect.registry.installations.values().any(|record| record.committed));
        connect.uninstall("worker", &workspace, spec).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(&settings).unwrap()).unwrap(), original);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn claude_upgrade_keeps_exact_legacy_managed_hooks_updatable() {
        let root = crate::test_support::protected_test_dir();
        let project = root.path().join("project");
        files::directory(&project, false).unwrap();
        let mut connect = Connect::open(&root.path().join("local")).unwrap();
        registration(&mut connect);
        let workspace = "W".repeat(43);
        let spec = Installation { host: "claude".into(), project: project.clone(), executable: std::env::current_exe().unwrap() };
        let installed = connect.install("worker", &workspace, spec).unwrap();
        let saved = connect.registry.installations.values().next().unwrap();
        let settings = std::fs::read(project.join(".claude/settings.local.json")).unwrap();
        let replacement = root.path().join("another-peerwork");
        let plan = claude_settings_update(Some(&settings), installed["server_name"].as_str().unwrap(),
            Some(&replacement), Some(saved), None).unwrap();
        assert!(plan.original.iter().all(Option::is_some));
        assert!(plan.installed.iter().all(Option::is_some));
        let value: Value = serde_json::from_slice(&plan.replacement.unwrap()).unwrap();
        for hooks in value["hooks"].as_object().unwrap().values() {
            let only = hooks.as_array().unwrap();
            assert_eq!(only.len(), 1);
            assert!(only[0]["hooks"][0]["command"].as_str().unwrap().contains("another-peerwork"));
        }
    }

    #[test]
    fn claude_uninstall_preserves_a_user_edited_configuration() {
        let root=crate::test_support::protected_test_dir();let project=root.path().join("project");files::directory(&project,false).unwrap();
        let mut c=Connect::open(&root.path().join("local")).unwrap();registration(&mut c);let ws="W".repeat(43);
        let spec=Installation{host:"claude".into(),project:project.clone(),executable:std::env::current_exe().unwrap()};
        let result=c.install("worker",&ws,spec.clone()).unwrap();let name=result["server_name"].as_str().unwrap();
        let mut value=json_config(&project.join(".mcp.json")).unwrap();value["mcpServers"][name]["args"]=json!(["user-edited"]);
        files::replace(&project.join(".mcp.json"),&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(c.uninstall("worker",&ws,spec).unwrap_err().code,"HOST_CONFIGURATION_CHANGED");
        assert_eq!(json_config(&project.join(".mcp.json")).unwrap(),value);
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
        let project_state = crate::onboarding_state::project(&project,"installations",true).unwrap().unwrap().join("ownership.state");
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
    fn codex_update_uses_committed_entry_and_reports_real_drift() {
        let root = crate::test_support::protected_test_dir();
        let project = root.path().join("project");
        files::directory(&project, false).unwrap();
        let mut connect = Connect::open(&root.path().join("local")).unwrap();
        registration(&mut connect);
        let workspace = "W".repeat(43);
        let executable = std::env::current_exe().unwrap();
        let spec = Installation { host: "codex".into(), project, executable: executable.clone() };
        let first = connect.install("worker", &workspace, spec).unwrap();
        let config = Path::new(first["mcp_configuration"].as_str().unwrap());
        let name = first["server_name"].as_str().unwrap();
        let old = std::fs::read_to_string(config).unwrap();
        let key = format!("[mcp_servers.{name}]");
        files::replace(config, old.replace(&key, &format!("[mcp_servers.'{name}']")).as_bytes()).unwrap();

        let binaries = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
        let second = binaries.path().join("peerwork-previous");
        let third = binaries.path().join("peerwork-next");
        for binary in [&second, &third] {
            std::fs::write(binary, b"synthetic executable").unwrap();
        }
        update_owned(&mut connect, "worker", &second).unwrap();
        update_owned(&mut connect, "worker", &third).unwrap();
        let updated = std::fs::read_to_string(config).unwrap();
        assert!(updated.contains(&third.to_string_lossy().to_string()));
        let edited = updated.replace(&third.to_string_lossy().to_string(), "/user/peerwork");
        files::replace(config, edited.as_bytes()).unwrap();
        let record = std::fs::read(connect.directory.join("connect.state")).unwrap();
        let error = update_owned(&mut connect, "worker", &third).unwrap_err();
        assert_eq!(error.code, "HOST_CONFIGURATION_CHANGED");
        assert_eq!(error.details.unwrap()["fields"], json!(["command"]));
        assert_eq!(std::fs::read_to_string(config).unwrap(), edited);
        assert_eq!(std::fs::read(connect.directory.join("connect.state")).unwrap(), record);
    }
    #[cfg(unix)]
    #[test]
    fn changed_project_cannot_inherit_prior_installation_ownership(){
        let root=crate::test_support::protected_test_dir();let project=root.path().join("project");files::directory(&project,false).unwrap();
        let mut c=Connect::open(&root.path().join("local")).unwrap();registration(&mut c);let ws="W".repeat(43);let spec=Installation{host:"agy".into(),project:project.clone(),executable:std::env::current_exe().unwrap()};
        c.install("worker",&ws,spec.clone()).unwrap();std::fs::rename(&project,root.path().join("original-project")).unwrap();std::fs::create_dir(&project).unwrap();
        assert!(matches!(c.install("worker",&ws,spec),Err(e)if e.code=="PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL"));assert!(!project.join(".agents").exists());
    }
    #[cfg(unix)]
    #[test]
    fn legacy_ownership_is_updated_in_place_without_a_second_ledger(){
        use std::os::unix::fs::DirBuilderExt;
        let root=crate::test_support::protected_test_dir();let project=root.path().join("project");files::directory(&project,false).unwrap();
        let mut c=Connect::open(&root.path().join("local")).unwrap();registration(&mut c);let ws="W".repeat(43);let spec=Installation{host:"agy".into(),project:project.clone(),executable:std::env::current_exe().unwrap()};c.install("worker",&ws,spec.clone()).unwrap();
        let external=crate::onboarding_state::project(&project,"installations",false).unwrap().unwrap();
        let raw=SecureStateStore::read_snapshot(&external.join("ownership.state"),65536).unwrap();let mut old:Value=serde_json::from_slice(&raw).unwrap();old.as_object_mut().unwrap().remove("project_identity");
        std::fs::remove_file(project.join(".agents/.peerwork-installation")).unwrap();let legacy=project.join(".agents/.peerwork-installation");std::fs::DirBuilder::new().mode(0o700).create(&legacy).unwrap();
        let store=SecureStateStore::open(&legacy.join("ownership.state")).unwrap();store.write_exact(&serde_json::to_vec(&old).unwrap()).unwrap();drop(store);std::fs::remove_dir_all(&external).unwrap();
        for item in c.registry.installations.values_mut(){item.project_identity=None;}c.save().unwrap();
        c.install("worker",&ws,spec.clone()).unwrap();let saved=SecureStateStore::read_snapshot(&legacy.join("ownership.state"),65536).unwrap();assert!(serde_json::from_slice::<Value>(&saved).unwrap()["project_identity"].is_object());assert!(!external.exists());
        c.uninstall("worker",&ws,spec).unwrap();assert!(!project.join(".agents/skills/peerwork/SKILL.md").exists());assert!(!external.exists());
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
            let mut project = ProjectFiles::open(&project,None,"agy").unwrap();
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
    pub(super) participant: String,
    workspace_id: String,
    spec: Installation,
    name: String,
    entry: Value,
    skill_hash: String,
    pub(super) committed: bool,
    #[serde(default)]
    entry_owned: bool,
    #[serde(default)]
    previous_entry: Option<Value>,
    #[serde(default)]
    previous_skill_hash: Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    project_identity: Option<Value>,
}
/// A Channel/background launch may use only its already committed original
/// host installation. Directory context disambiguates installations, never a
/// model conversation or a new receiving destination.
pub(super) fn presentation_registration(connect:&Connect,participant:&str,workspace:&str,kind:&str,launch:Option<(&str,&[&str])>)->Result<Option<String>> {
    let host=match kind {"MCP_STDIO_CHANNEL"=>"claude","MCP_BACKGROUND_TOOL"=>"agy",_=>return Err(local("PRESENTATION_TARGET_INVALID"))};
    let candidates=connect.registry.installations.iter().filter(|(_,entry)| {
        entry.committed && entry.participant==participant && entry.spec.host==host && match launch {
            Some((name,workspaces))=>entry.name==name && workspaces.contains(&entry.workspace_id.as_str()),
            None=>entry.workspace_id==workspace,
        }
    }).collect::<Vec<_>>();
    if candidates.len()<=1 {return Ok(candidates.first().map(|(id,_)|(*id).clone()));}
    let cwd=std::env::current_dir().ok().and_then(|path|std::fs::canonicalize(path).ok());
    let exact=candidates.iter().filter(|(_,entry)|cwd.as_ref()==Some(&entry.spec.project)).collect::<Vec<_>>();
    if exact.len()==1 {return Ok(Some(exact[0].0.clone()));}
    Err(local("PRESENTATION_ORIGINAL_INSTALLATION_SELECTION_REQUIRED"))
}
pub(super) fn codex_handoff_installation(
    connect: &Connect,
    participant: &str,
    workspace: &str,
) -> Result<(PathBuf, String, Value)> {
    let mut installations = connect.registry.installations.values().filter(|record| {
        record.committed && record.spec.host == "codex"
            && record.participant == participant && record.workspace_id == workspace
    });
    let record = installations.next().ok_or_else(|| local("CODEX_HANDOFF_INSTALLATION_REQUIRED"))?;
    if installations.next().is_some() {
        return Err(local("CODEX_HANDOFF_INSTALLATION_AMBIGUOUS"));
    }
    let identity = crate::onboarding_project::Directory::open(&record.spec.project)?.identity()?;
    if record.project_identity.as_ref() != Some(&identity) {
        return Err(local("CODEX_HANDOFF_PROJECT_CHANGED"));
    }
    Ok((record.spec.project.clone(), record.name.clone(), record.entry.clone()))
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
    let mut value=json!({"command":spec.executable,"args":["agent","--local",directory,"--participant",participant,"--workspace",workspace,"mcp"]});
    if spec.host=="claude" {
        value["type"]=json!("stdio");
        value["args"].as_array_mut().unwrap().push(json!("--claude-channel"));
    }
    if spec.host=="agy" {
        // The host owns this pending call and delivers its completion to the
        // calling conversation. Native RPC/business operations keep their own
        // deadlines; an idle listener must not wake the model on a timer.
        value["tools"]=json!({"peerwork_listen":{"eager":true,"background":"always"}});
        value["timeoutSeconds"]=json!(-1);
    }
    if spec.host=="opencode" {
        let mut command=vec![json!(spec.executable)];
        command.extend(value["args"].as_array().unwrap().iter().cloned());
        value=json!({"type":"local","command":command,"protocol":"2026-07-28","codemode":false});
    }
    value
}
#[test]
fn agy_background_configuration_is_scoped_to_the_original_native_entry() {
    let root=crate::test_support::protected_test_dir();
    let mut spec=Installation{host:"agy".into(),project:root.path().join("project"),executable:root.path().join("peerwork")};
    let value=entry(&root.path().join("local"),"original-peer",&"W".repeat(43),&spec);
    assert_eq!(value["tools"],json!({"peerwork_listen":{"eager":true,"background":"always"}}));
    assert_eq!(value["timeoutSeconds"],-1);
    assert_eq!(value["args"][4],"original-peer");
    assert!(!value.to_string().contains("dangerously"));
    spec.host="codex".into();assert!(entry(root.path(),"original-peer",&"W".repeat(43),&spec).get("tools").is_none());
}
fn skill_root(host:&str)->&str {match host {"claude"=>".claude","opencode"=>".opencode",_=>".agents"}}
fn config_location(host:&str)->(Option<&str>,&str) {
    match host {"codex"=>(Some(".codex"),"config.toml"),"claude"=>(None,".mcp.json"),"opencode"=>(Some(".opencode"),"opencode.json"),_=>(Some(".agents"),"mcp_config.json")}
}
fn server_entries<'a>(value:&'a mut Value,host:&str)->Result<&'a mut serde_json::Map<String,Value>> {
    if host=="opencode" {
        if value.get("mcp").is_none(){value["mcp"]=json!({"servers":{}});}
        if !value["mcp"].is_object() || value["mcp"].as_object().unwrap().keys().any(|key|!matches!(key.as_str(),"servers"|"timeout")) {
            return Err(local("HOST_CONFIGURATION_REQUIRES_OPENCODE_V2_MCP_SERVERS"));
        }
        if value["mcp"].get("servers").is_none(){value["mcp"]["servers"]=json!({});}
        value["mcp"]["servers"].as_object_mut().ok_or_else(||local("HOST_CONFIGURATION_INVALID"))
    }else{
        if value.get("mcpServers").is_none(){value["mcpServers"]=json!({});}
        value["mcpServers"].as_object_mut().ok_or_else(||local("HOST_CONFIGURATION_INVALID"))
    }
}
#[cfg(target_os = "linux")]
type ClaudeHookClaims = [Option<String>; 2];

#[cfg(target_os = "linux")]
struct ClaudeHookOwnership {
    store: OwnershipStore,
    claims: std::collections::BTreeMap<String, ClaudeHookClaims>,
}

#[cfg(target_os = "linux")]
impl ClaudeHookOwnership {
    // Share the project installation lock. Keep ownership in a separate
    // envelope so existing frontends can still read their registry on rollback.
    fn open(project: &Path) -> Result<Self> {
        let directory = crate::onboarding_state::project(project, "claude-installations", true)?.unwrap();
        let store = OwnershipStore::protected(&directory.join("hooks.state"))?;
        let claims: std::collections::BTreeMap<String, ClaudeHookClaims> = match store.read_exact()? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| local("CLAUDE_CHANNEL_HOOK_OWNERSHIP_INVALID"))?,
            None => std::collections::BTreeMap::new(),
        };
        if claims.len() > 64 {
            return Err(local("CLAUDE_CHANNEL_HOOK_OWNERSHIP_INVALID"));
        }
        Ok(Self { store, claims })
    }

    fn save(&mut self, reference: &str, claims: Option<ClaudeHookClaims>) -> Result<()> {
        if self.claims.get(reference) == claims.as_ref() {
            return Ok(());
        }
        match claims {
            Some(claims) => { self.claims.insert(reference.into(), claims); }
            None => { self.claims.remove(reference); }
        };
        let bytes = serde_json::to_vec(&self.claims).map_err(|_| local("CLAUDE_CHANNEL_HOOK_OWNERSHIP_INVALID"))?;
        self.store.write_exact(&bytes)
    }
}

#[cfg(target_os = "linux")]
struct ClaudeSettingsPlan {
    replacement: Option<Vec<u8>>,
    original: ClaudeHookClaims,
    installed: ClaudeHookClaims,
}

#[cfg(target_os = "linux")]
fn claude_settings_update(
    bytes: Option<&[u8]>,
    name: &str,
    executable: Option<&Path>,
    prior: Option<&Installed>,
    claims: Option<&ClaudeHookClaims>,
) -> Result<ClaudeSettingsPlan> {
    let invalid = || local("CLAUDE_CHANNEL_SETTINGS_INVALID");
    let mut value = match bytes {
        Some(bytes) => peerwork_core::strict_json::parse_strict_json(bytes).map_err(|_| invalid())?,
        None => json!({}),
    };
    let before = value.clone();
    let root = value.as_object_mut().ok_or_else(invalid)?;
    let hooks = root.entry("hooks").or_insert_with(|| json!({})).as_object_mut().ok_or_else(invalid)?;
    let mut original = [None, None];
    let mut installed = [None, None];
    for (index, (event, suffix, matcher)) in [
        ("SessionStart", "start", Some("startup|resume")),
        ("SessionEnd", "end", None),
    ].into_iter().enumerate() {
        let entry = |path: &Path| -> Result<Value> {
            let executable = crate::claude_channel_launch::shell_executable(path)?;
            let mut entry = json!({"hooks":[{"type":"command",
                "command":format!("{executable} agent claude-session-{suffix} {name}"),"timeout":1}]});
            if let Some(matcher) = matcher { entry["matcher"] = json!(matcher); }
            Ok(entry)
        };
        let wanted = executable.map(entry).transpose()?;
        let old = prior.map(|prior| entry(&prior.spec.executable)).transpose()?;
        let previous = prior.and_then(|prior| prior.previous_entry.as_ref())
            .and_then(|entry| entry["command"].as_str()).map(Path::new).map(entry).transpose()?;
        let entries = hooks.entry(event).or_insert_with(|| json!([])).as_array_mut().ok_or_else(invalid)?;
        let digest = |hook: &Value| sha256_hex(hook.to_string().as_bytes());
        // An older committed MCP installation had no per-hook receipt.
        // Only its exact legacy configuration is eligible for migration.
        original[index] = match claims {
            Some(claims) => claims[index].clone(),
            None => old.as_ref().filter(|hook| prior.is_some_and(|p| p.entry_owned && p.committed)
                && entries.contains(hook)).map(digest),
        };
        let owns = |hook: &Value| original[index].as_ref().is_some_and(|expected| &digest(hook) == expected);
        if let Some(wanted) = &wanted {
            for other in entries.iter().filter(|other| *other != wanted && !owns(other)) {
                let same_command = [Some(wanted), old.as_ref(), previous.as_ref()].into_iter().flatten()
                    .any(|known| other["hooks"].as_array().is_some_and(|handlers| handlers.iter()
                        .any(|handler| handler["command"] == known["hooks"][0]["command"])));
                if same_command {
                    let mut error = local("CLAUDE_CHANNEL_SETTINGS_CHANGED");
                    error.details = Some(json!({"file":".claude/settings.local.json", "event":event,
                        "next_action":"REVIEW_ORIGINAL_CLAUDE_HOOK"}));
                    return Err(error);
                }
            }
        }
        entries.retain(|other| wanted.as_ref() == Some(other) || !owns(other));
        if let Some(wanted) = wanted {
            if entries.contains(&wanted) {
                if owns(&wanted) { installed[index] = Some(digest(&wanted)); }
            } else {
                installed[index] = Some(digest(&wanted));
                entries.push(wanted);
            }
        }
        if entries.is_empty() && !before["hooks"][event].as_array().is_some_and(Vec::is_empty) {
            hooks.remove(event);
        }
    }
    if hooks.is_empty() && before.get("hooks").is_none_or(|hooks| hooks.as_object().is_some_and(|hooks| !hooks.is_empty())) {
        root.remove("hooks");
    }
    let replacement = (value != before).then(|| serde_json::to_vec_pretty(&value)).transpose().map_err(|_| invalid())?;
    Ok(ClaudeSettingsPlan { replacement, original, installed })
}

fn changed_config(host:&str,path:&Path,name:&str)->ParticipantError {
    let mut error=local("HOST_CONFIGURATION_CHANGED");
    if host=="opencode" {error.details=Some(json!({"file":path,"field":format!("mcp.servers.{name}"),"next_action":"RESTORE_OR_RESELECT_ORIGINAL_OWNED_ENTRY"}));}
    error
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectOwnership {
    references: std::collections::BTreeSet<String>,
    skill_owned: bool,
    skill_hash: Option<String>,
    pending_skill_hash: Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    project_identity: Option<Value>,
}
use crate::onboarding_store::Store as OwnershipStore;
struct ProjectFiles {
    store: OwnershipStore,
    ownership: ProjectOwnership,
}
pub(super) fn matches_installation(connect:&Connect,project:&Path,host:&str,name:&str,entry:&Value)->bool {
    connect.registry.installations.values().any(|record|record.committed && record.entry_owned
        && record.spec.project==project && record.spec.host==host && record.name==name && record.entry==*entry
        && record.project_identity.as_ref().is_none_or(|wanted|crate::onboarding_project::Directory::open(project).and_then(|p|p.identity()).as_ref().ok()==Some(wanted)))
}
impl ProjectFiles {
    fn open(project:&Path,own_reference:Option<&str>,host:&str)->Result<Self>{
        let context=crate::onboarding_project::Directory::open(project)?;
        let identity=context.identity()?;
        let agents=context.child(skill_root(host),false,false)?.ok_or_else(||local("HOST_INSTALLATION_RECOVERY_REQUIRED"))?;
        const MARKER:&str=".peerwork-installation";
        let kind=agents.kind(MARKER)?;
        let legacy=kind==Some("DIRECTORY");
        let store=if legacy {
            let directory=agents.child(MARKER,false,true)?.unwrap();
            OwnershipStore::anchored(directory,"ownership.state",true)?
        }else{
            if kind==Some("OTHER"){return Err(local("HOST_INSTALLATION_RECOVERY_REQUIRED"))}
            let directory=crate::onboarding_state::project(project,match host {"claude"=>"claude-installations","opencode"=>"opencode-installations",_=>"installations"},true)?.unwrap();
            if kind.is_some() && !directory.join("ownership.state").is_file(){return Err(local("HOST_INSTALLATION_ORIGINAL_STATE_REQUIRED"))}
            let store=SecureStateStore::open(&directory.join("ownership.state")).map_err(|_|local("HOST_INSTALLATION_ALREADY_OWNED_OR_UNSAFE"))?;
            OwnershipStore::Protected(store)
        };
        let mut ownership:ProjectOwnership=match store.read_exact()?{
            Some(bytes)=>serde_json::from_value(peerwork_core::strict_json::parse_strict_json(&bytes).map_err(|_|local("HOST_INSTALLATION_RECOVERY_REQUIRED"))?).map_err(|_|local("HOST_INSTALLATION_RECOVERY_REQUIRED"))?,
            None=>ProjectOwnership::default(),
        };
        if ownership.references.len()>64 || ownership.project_identity.as_ref().is_some_and(|wanted|wanted!=&identity){return Err(local("PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL"))}
        if legacy && ownership.project_identity.is_none() {
            let mut proven=own_reference.is_some_and(|r|ownership.references.contains(r));
            if !proven && !ownership.references.is_empty(){
                for binding in super::discovery::project_bindings(project,None)? {
                    let original=Connect::inspect(&binding.directory)?;
                    if original.registry.installations.iter().any(|(key,record)|record.spec.project==project && ownership.references.contains(&reference(&binding.directory,key))) {proven=true;break}
                }
            }
            if !ownership.references.is_empty() && !proven {return Err(local("HOST_INSTALLATION_LEGACY_OWNER_CONFIRMATION_REQUIRED"))}
            ownership.project_identity=Some(identity.clone());
            store.write_exact(&serde_json::to_vec(&ownership).map_err(|_|local("HOST_INSTALLATION_WRITE_FAILED"))?)?;
        }
        if !legacy {
            let marker=json!({"format":"peerwork.user-installation.v1","project_key":sha256_hex(project.to_string_lossy().as_bytes())});
            if let Some(existing)=agents.read(MARKER,65536,false)? {
                if peerwork_core::strict_json::parse_strict_json(&existing).ok().as_ref()!=Some(&marker){return Err(local("HOST_INSTALLATION_CHANGED"))}
            }else{
                // A public format fence stops an older installer from creating
                // another ownership store for the same project. No secrets.
                ownership.project_identity=Some(identity);
                store.write_exact(&serde_json::to_vec(&ownership).map_err(|_|local("HOST_INSTALLATION_WRITE_FAILED"))?)?;
                agents.replace(MARKER,None,&serde_json::to_vec(&marker).unwrap())?;
            }
            if ownership.project_identity.is_none(){return Err(local("HOST_INSTALLATION_RECOVERY_REQUIRED"))}
        }
        context.verify()?;Ok(Self{store,ownership})
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
    let begin = format!("# peerwork-owned {name} begin");
    let end = format!("# peerwork-owned {name} end");
    let mut offset = 0;
    let mut start = None;
    let mut stop = None;
    for line in old.split_inclusive('\n') {
        if line.trim() == begin {
            if start.is_some() || stop.is_some() {
                return Err(local("HOST_CONFIGURATION_CONFLICT"));
            }
            // Include the separator emitted by codex_block, if present.
            start = Some(if old[..offset].ends_with("\n\n") || &old[..offset] == "\n" {
                offset - 1
            } else {
                offset
            });
        } else if line.trim() == end {
            if start.is_none() || stop.is_some() {
                return Err(local("HOST_CONFIGURATION_CONFLICT"));
            }
            stop = Some(offset + line.len());
        }
        offset += line.len();
    }
    let existing = parsed.get("mcp_servers").and_then(|servers| servers.get(name));
    let (prefix, suffix) = match (start, stop) {
        (Some(start), Some(stop)) => {
            // The marked region must contain only the managed table. In
            // particular, a marker inside a multiline value conveys no ownership.
            let block = old[start..stop].parse::<toml_edit::DocumentMut>()
                .map_err(|_| local("HOST_CONFIGURATION_CONFLICT"))?;
            let servers = block.get("mcp_servers").and_then(|item| item.as_table())
                .filter(|servers| block.as_table().len() == 1 && servers.len() == 1)
                .ok_or_else(|| local("HOST_CONFIGURATION_CONFLICT"))?;
            let entry = servers.get(name).and_then(|item| item.as_table())
                .ok_or_else(|| local("HOST_CONFIGURATION_CONFLICT"))?;
            let prefix = &old[..start];
            let suffix = &old[stop..];
            let outside = format!("{prefix}{suffix}").parse::<toml_edit::DocumentMut>()
                .map_err(|_| local("HOST_CONFIGURATION_CONFLICT"))?;
            if outside.get("mcp_servers").and_then(|servers| servers.get(name)).is_some() {
                return Err(local("HOST_CONFIGURATION_CONFLICT"));
            }
            let actual = json!({
                "command": entry.get("command").and_then(|value| value.as_str()),
                "args": entry.get("args").and_then(|value| value.as_array())
                    .and_then(|args| args.iter().map(|arg| arg.as_str()).collect::<Option<Vec<_>>>()),
            });
            if entry.len() != 2 || (&actual != wanted && prior != Some(&actual)) {
                let expected = prior.unwrap_or(wanted);
                let mut fields: Vec<&str> = ["command", "args"].into_iter()
                    .filter(|key| actual[*key] != expected[*key]).collect();
                if entry.iter().any(|(key, _)| !matches!(key, "command" | "args")) {
                    fields.push("additional_fields");
                }
                let mut error = local("HOST_CONFIGURATION_CHANGED");
                error.details = Some(json!({"entry": format!("mcp_servers.{name}"), "fields": fields,
                    "next_action":"RESTORE_OR_RESELECT_ORIGINAL_OWNED_ENTRY"}));
                return Err(error);
            }
            if !remove && &actual == wanted {
                return Ok(None);
            }
            (prefix, suffix)
        }
        (None, None) if existing.is_none() => (old.as_str(), ""),
        _ => return Err(local("HOST_CONFIGURATION_CONFLICT")),
    };
    let desired = if remove { String::new() } else { codex_block(name, wanted) };
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
        mut spec: Installation,
    ) -> Result<Value> {
        self.require_writer()?;
        if !self.registry.participants.contains_key(participant)
            || !token(workspace)
            || !["codex", "agy", "claude", "opencode"].contains(&spec.host.as_str())
            || !spec.executable.is_absolute()
            || !std::fs::metadata(&spec.executable).is_ok_and(|m| m.is_file())
        {
            return Err(local("HOST_INSTALLATION_SELECTION_INVALID"));
        }
        spec.executable=persistent_executable(&spec.executable)?;
        let project_root = crate::onboarding_project::Directory::open(&spec.project)?;
        let project_identity = project_root.identity()?;
        let key = id(participant, workspace, &spec);
        let reference = reference(&self.directory, &key);
        let name = server_name(&self.directory, participant, workspace, &spec);
        let wanted = entry(&self.directory, participant, workspace, &spec);
        let prior = self.registry.installations.get(&key).cloned();
        if prior.as_ref().and_then(|p|p.project_identity.as_ref()).is_some_and(|old|old!=&project_identity){return Err(local("PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL"))}
        if prior.is_none() && self.registry.installations.len() >= 32 {
            return Err(local("HOST_INSTALLATION_LIMIT"));
        }
        let agents = project_root.child(skill_root(&spec.host),true,false)?.unwrap();
        // This project-scoped owner serializes Peerwork installations from
        // distinct identity registries and tracks shared Skill provenance.
        let mut project = ProjectFiles::open(&spec.project,prior.as_ref().map(|_|reference.as_str()),&spec.host)?;
        if !project.ownership.references.contains(&reference)
            && project.ownership.references.len() >= 64
        {
            return Err(local("HOST_INSTALLATION_LIMIT"));
        }
        let (subdirectory,config_name)=config_location(&spec.host);
        let config_directory=match subdirectory {Some(name)=>project_root.child(name,true,false)?.unwrap(),None=>crate::onboarding_project::Directory::open(&spec.project)?};
        let config = config_directory.path().join(config_name);
        let old_config = config_directory.read(config_name,256*1024,false)?;
        let new_config = if spec.host == "codex" {
            codex_update(
                old_config.clone(),
                &name,
                &wanted,
                prior
                    .as_ref()
                    .filter(|p| p.entry_owned)
                    .map(|p| if p.committed { &p.entry } else { p.previous_entry.as_ref().unwrap_or(&p.entry) }),
                false,
            )?
        } else {
            let mut value = if spec.host=="opencode" && old_config.is_none(){json!({})}else{parse_json_config(old_config.as_deref())?};
            let entries=server_entries(&mut value,&spec.host)?;
            let existing = entries.get(&name).unwrap_or(&Value::Null);
            if !existing.is_null()
                && existing != &wanted
                && prior.as_ref().is_none_or(|p| {
                    !p.entry_owned
                        || (existing != &p.entry && p.previous_entry.as_ref() != Some(existing))
                })
            {
                return Err(changed_config(&spec.host,&config,&name));
            }
            if existing == &wanted {
                None
            } else {
                entries.insert(name.clone(),wanted.clone());
                Some(
                    serde_json::to_vec_pretty(&value)
                        .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?,
                )
            }
        };
        #[cfg(target_os = "linux")]
        let claude_settings = if spec.host == "claude" {
            let ownership = ClaudeHookOwnership::open(&spec.project)?;
            let old = agents.read("settings.local.json", 256 * 1024, false)?;
            let plan = claude_settings_update(old.as_deref(), &name, Some(&spec.executable), prior.as_ref(),
                ownership.claims.get(&reference))?;
            Some((ownership, old, plan))
        } else {
            None
        };
        let entry_owned = prior.as_ref().is_some_and(|p| p.entry_owned);
        // A plan to publish is not proof of publication. On a lost pre-write
        // attempt, an identical file encountered later remains user-owned.
        let skills=agents.child("skills",true,false)?.unwrap();
        let skill_dir=skills.child("peerwork",true,false)?.unwrap();
        let skill=skill_dir.path().join("SKILL.md");
        let existing_skill=skill_dir.read("SKILL.md",65536,false)?;
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
        project.ownership.references.insert(reference.clone());
        if existing_skill.as_deref() != Some(SKILL.as_bytes())
            || (project.ownership.skill_owned
                && project.ownership.skill_hash.as_ref() != Some(&hash))
        {
            project.ownership.pending_skill_hash = Some(hash.clone());
        }
        project.save()?;
        #[cfg(target_os = "linux")]
        let mut claude_settings = claude_settings;
        #[cfg(target_os = "linux")]
        if let Some((ownership, _, plan)) = &mut claude_settings {
            ownership.save(&reference, Some(plan.original.clone()))?;
        }
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
            project_identity: Some(project_identity.clone()),
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
                || p.project_identity.as_ref() != Some(&project_identity)
                || !p.committed
        }) {
            self.registry.installations.insert(key.clone(), record);
            self.save()?;
        }
        if let Some(bytes) = new_config {
            config_directory.replace(config_name,old_config.as_deref(),&bytes)?;
            self.registry
                .installations
                .get_mut(&key)
                .unwrap()
                .entry_owned = true;
            self.save()?;
        }
        #[cfg(target_os = "linux")]
        if let Some((mut ownership, old, plan)) = claude_settings {
            if let Some(new) = plan.replacement {
                agents.replace("settings.local.json", old.as_deref(), &new)?;
            }
            ownership.save(&reference, Some(plan.installed))?;
        }
        if existing_skill.as_deref() != Some(SKILL.as_bytes()) {
            skill_dir.replace("SKILL.md",existing_skill.as_deref(),SKILL.as_bytes())?;
            project.ownership.skill_owned = true;
        }
        if let Some(hash) = project.ownership.pending_skill_hash.take() {
            if project.ownership.skill_owned {
                project.ownership.skill_hash = Some(hash);
            }
            project.save()?;
        }
        project_root.verify()?;
        if !self.registry.installations[&key].committed {
            self.registry.installations.get_mut(&key).unwrap().committed = true;
            self.save()?;
        }
        let mut result=json!({"state":"HOST_INTEGRATION_INSTALLED","host":spec.host,"server_name":name,"participant":participant,"workspace_id":workspace,
            "mcp_configuration":config,"skill":skill,"current_session_tools":"NOT_ATTESTED","host_delivery":"NOT_ATTESTED",
            "next_action":"REFRESH_HOST_AND_CALL_PEERWORK_CONTEXT","identity_files_copied":false});
        result["automatic_startup"] = self.enroll_startup(participant)?;
        if spec.host=="claude" {
            result["channel"]=json!({"state":"ACTIVATION_REQUIRED","maturity":"RESEARCH_PREVIEW",
                "start_argv":["claude","--resume","SESSION_ID","--dangerously-load-development-channels",format!("server:{name}")],
                "host_acceptance":"NOT_ATTESTED","next_action":"ENABLE_CHANNEL_IN_CLAUDE_AND_VERIFY_A_REAL_MESSAGE"});
        }
        if spec.host=="opencode" {
            result["supported_host_api"]=json!("OPENCODE_V2");
            result["host_delivery"]=json!("VERIFY_BOUND_OPENCODE_SESSION");
        }
        if spec.host=="agy" {
            result["background_receiving"]=json!({"state":"ARM_IN_CURRENT_CONVERSATION","tool":"peerwork_listen",
                "arguments":{},"transport":"MCP_BACKGROUND_TOOL","requires_unbound_native_inbox":true,
                "next_action":"REFRESH_ORIGINAL_MCP_THEN_ARM_LISTENER_AND_READ_SELF_TEST_BATCH",
                "model_wake":"NOT_ATTESTED","new_agent_process":false});
        }
        Ok(result)
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
        let project_root=crate::onboarding_project::Directory::open(&spec.project)?;
        if owned.project_identity.as_ref().is_some_and(|wanted|project_root.identity().as_ref().ok()!=Some(wanted)) {return Err(local("PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL"))}
        let (subdirectory,config_name)=config_location(&spec.host);
        let config_directory=match subdirectory {Some(name)=>project_root.child(name,false,false)?.ok_or_else(||local("HOST_CONFIGURATION_CHANGED"))?,None=>crate::onboarding_project::Directory::open(&spec.project)?};
        let own_reference=reference(&self.directory,&key);
        let mut project=ProjectFiles::open(&spec.project,Some(&own_reference),&spec.host)?;
        let old_config=config_directory.read(config_name,256*1024,false)?;
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
            let entries=server_entries(&mut value,&spec.host)?;
            if !entries.contains_key(&owned.name) {
                None
            } else {
                if entries[&owned.name] != owned.entry
                    && (owned.committed
                        || owned.previous_entry.as_ref() != Some(&entries[&owned.name]))
                {
                    return Err(changed_config(&spec.host,&config_directory.path().join(config_name),&owned.name));
                }
                entries.remove(&owned.name);
                Some(
                    serde_json::to_vec_pretty(&value)
                        .map_err(|_| local("HOST_CONFIGURATION_INVALID"))?,
                )
            }
        };
        let shared = project
            .ownership
            .references
            .iter()
            .any(|r| r != &own_reference);
        let agents=project_root.child(skill_root(&spec.host),false,false)?.ok_or_else(||local("HOST_SKILL_CHANGED"))?;
        let skill_dir=agents.child("skills",false,false)?.map(|d|d.child("peerwork",false,false)).transpose()?.flatten();
        let existing_skill=match &skill_dir {Some(dir)=>dir.read("SKILL.md",65536,false)?,None=>None};
        let remove_skill = !shared
            && project.ownership.skill_owned
            && existing_skill.as_ref().is_some_and(|bytes| {
                let hash = sha256_hex(bytes);
                project.ownership.skill_hash.as_ref() == Some(&hash)
                    || project.ownership.pending_skill_hash.as_ref() == Some(&hash)
            });
        #[cfg(target_os = "linux")]
        let claude_hook_cleanup = if spec.host == "claude" {
            let mut ownership = ClaudeHookOwnership::open(&spec.project)?;
            let old = agents.read("settings.local.json", 256 * 1024, false)?;
            let plan = claude_settings_update(old.as_deref(), &owned.name, None, Some(&owned),
                ownership.claims.get(&own_reference))?;
            ownership.save(&own_reference, Some(plan.original))?;
            if let Some(new) = plan.replacement {
                agents.replace("settings.local.json", old.as_deref(), &new)?;
            }
            // An interrupted uninstall still has a committed installation
            // record. Keep the empty claim so a retry cannot infer ownership
            // of a surviving user hook from the legacy MCP record.
            ownership.save(&own_reference, Some([None, None]))?;
            Some(ownership)
        } else {
            None
        };
        if let Some(bytes) = new_config {
            config_directory.replace(config_name,old_config.as_deref(),&bytes)?;
        }
        if remove_skill {
            skill_dir.as_ref().unwrap().remove("SKILL.md",existing_skill.as_deref().unwrap())?;
        }
        let skill_retained = existing_skill.is_some() && !remove_skill;
        project.ownership.references.remove(&own_reference);
        if remove_skill {
            project.ownership.skill_owned = false;
            project.ownership.skill_hash = None;
            project.ownership.pending_skill_hash = None;
        }
        project.save()?;
        project_root.verify()?;
        self.registry.installations.remove(&key);
        self.save()?;
        #[cfg(target_os = "linux")]
        if let Some(mut ownership) = claude_hook_cleanup {
            ownership.save(&own_reference, None)?;
        }
        Ok(
            json!({"state":"HOST_INTEGRATION_REMOVED","identity_and_recovery_retained":true,"remote_grants_changed":false,"skill_retained":skill_retained}),
        )
    }
}

/// Inventory only installations already recorded for this exact participant.
/// A matching user-authored entry is not installation ownership.
pub(super) fn update_inventory(connect:&Connect, participant:&str)->Vec<Value> {
    connect.registry.installations.values().filter(|r|r.participant==participant).map(|r|
        json!({"host":r.spec.host,"project":r.spec.project,"workspace_id":r.workspace_id,
            "server_name":r.name,"installed_executable":r.spec.executable,
            "owned":r.entry_owned,"committed":r.committed,"loaded_version":"UNKNOWN"})).collect()
}
pub(super) fn update_owned(connect:&mut Connect,participant:&str,executable:&Path)->Result<Vec<Value>> {
    let selected:Vec<_>=connect.registry.installations.values().filter(|r|r.participant==participant && r.entry_owned)
        .map(|r|(r.workspace_id.clone(),Installation{executable:executable.into(),..r.spec.clone()})).collect();
    selected.into_iter().map(|(workspace,spec)|connect.install(participant,&workspace,spec)).collect()
}
