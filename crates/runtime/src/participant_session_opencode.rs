//! Managed independent conversations on the owner's registered OpenCode V2 service.
use crate::communication_host::{opencode::Client, operation::Budget};
use peerwork_core::crypto::sha256_hex;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, &'static str>;
const OWNERSHIP_KEY: &str = "peerwork_managed_session_v1";

struct Target {
    id: String,
    ownership: String,
}

impl Target {
    fn new(file: &Path, directory: &str, marker: &str) -> Result<Self> {
        if marker.is_empty() || marker.len() > 256 || marker.chars().any(char::is_control) {
            return Err("MANAGED_SESSION_MARKER_INVALID");
        }
        let file = file.to_str().ok_or("OPENCODE_SERVICE_SELECTION_REQUIRED")?;
        let ownership = sha256_hex(
            json!([OWNERSHIP_KEY, file, directory, marker])
                .to_string()
                .as_bytes(),
        );
        Ok(Self {
            id: format!("ses_{ownership}"),
            ownership,
        })
    }

    fn title(&self) -> String {
        format!("Peerwork session {}", &self.ownership[..12])
    }

    fn verify(&self, session: &Value, directory: &str) -> Result<()> {
        if session["id"] != self.id
            || session["location"]["directory"] != directory
            || !session["time"]["archived"].is_null()
            || !session["parentID"].is_null()
            || session["metadata"][OWNERSHIP_KEY] != self.ownership
        {
            return Err("OPENCODE_MANAGED_SESSION_MISMATCH");
        }
        Ok(())
    }

    fn verify_selected(&self, client: &Client, directory: &str, session_id: &str) -> Result<()> {
        if session_id != self.id {
            return Err("OPENCODE_MANAGED_SESSION_MISMATCH");
        }
        self.verify(&client.session(session_id, directory)?, directory)
    }
}

async fn with_client<T: Send + 'static>(
    file: PathBuf,
    directory: PathBuf,
    operation: impl FnOnce(&Client, &Path, &str) -> Result<T> + Send + 'static,
) -> Result<T> {
    let executor = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        if !file.is_absolute() {
            return Err("OPENCODE_SERVICE_SELECTION_REQUIRED");
        }
        if !directory.is_absolute()
            || !directory.is_dir()
            || std::fs::canonicalize(&directory).ok().as_ref() != Some(&directory)
        {
            return Err("PROJECT_CONTEXT_INVALID");
        }
        let directory = directory.to_str().ok_or("PROJECT_CONTEXT_INVALID")?;
        let budget = Budget::new(Duration::from_secs(10));
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "HOST_CONFIG_INVALID")?;
        let client = Client::open(&file, http, executor, budget)?;
        if !client.authenticated() {
            return Err("OPENCODE_SERVICE_AUTHENTICATION_REQUIRED");
        }
        operation(&client, &file, directory)
    })
    .await
    .map_err(|_| "HOST_TASK_FAILED")?
}

pub(crate) fn adapter(file: &Path, directory: &Path, session_id: &str) -> Value {
    json!({"kind":"opencode","service_file":file,"session_id":session_id,"directory":directory})
}

pub(crate) async fn launch(
    file: PathBuf,
    directory: PathBuf,
    marker: String,
    create: bool,
) -> Result<String> {
    with_client(file, directory, move |client, file, directory| {
        let target = Target::new(file, directory, &marker)?;
        match client.session(&target.id, directory) {
            Ok(existing) => target.verify(&existing, directory)?,
            Err("OPENCODE_RESOURCE_NOT_FOUND") if create => {
                // OpenCode V2 accepts a caller-selected ID and returns that
                // session if creation wins elsewhere. The marker must agree
                // before using a result from either side of that race.
                let payload = json!({
                    "id": &target.id,
                    "title": target.title(),
                    "location": {"directory":directory},
                    "metadata": {(OWNERSHIP_KEY): &target.ownership}
                });
                let created = client.request("POST", "/api/session", Some(&payload))?;
                target.verify(&created["data"], directory)?;
            }
            Err(error) => return Err(error),
        }
        Ok(target.id)
    })
    .await
}

pub(crate) async fn validate(
    file: PathBuf,
    directory: PathBuf,
    marker: String,
    session_id: String,
) -> Result<()> {
    with_client(file, directory, move |client, file, directory| {
        Target::new(file, directory, &marker)?.verify_selected(client, directory, &session_id)
    })
    .await
}

fn positively_idle(client: &Client, session_id: &str) -> Result<bool> {
    let active = client.request("GET", "/api/session/active", None)?;
    let sessions = active["data"]
        .as_object()
        .ok_or("OPENCODE_SESSION_ACTIVITY_UNKNOWN")?;
    if sessions
        .values()
        .any(|session| session["type"] != "running")
    {
        return Err("OPENCODE_SESSION_ACTIVITY_UNKNOWN");
    }
    Ok(!sessions.contains_key(session_id))
}

pub(crate) async fn idle(
    file: PathBuf,
    directory: PathBuf,
    marker: String,
    session_id: String,
) -> Result<bool> {
    with_client(file, directory, move |client, file, directory| {
        Target::new(file, directory, &marker)?.verify_selected(client, directory, &session_id)?;
        positively_idle(client, &session_id)
    })
    .await
}

fn project_resource(resource: &str, directory: &str) -> String {
    let mut url = reqwest::Url::parse("http://localhost/").expect("valid static URL");
    url.set_path(resource);
    url.query_pairs_mut()
        .append_pair("location[directory]", directory);
    format!(
        "{}?{}",
        url.path(),
        url.query().expect("directory parameter")
    )
}

fn peerwork_name(name: &str) -> bool {
    name == "peerwork" || name.starts_with("peerwork-")
}

fn verify_entries(config: &Value, servers: &Value, name: &str, expected: &Value) -> Result<()> {
    let expected_executable = expected["command"][0]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("OPENCODE_MCP_CONFIGURATION_UNVERIFIED")?;
    let documents = config
        .as_array()
        .ok_or("OPENCODE_MCP_CONFIGURATION_UNVERIFIED")?;
    let mut configured = BTreeMap::<&str, &Value>::new();
    for doc in documents {
        if doc["type"] == "document" {
            if let Some(entries) = doc["info"]["mcp"].get("servers") {
                let entries = entries
                    .as_object()
                    .ok_or("OPENCODE_MCP_CONFIGURATION_UNVERIFIED")?;
                configured.extend(
                    entries
                        .iter()
                        .map(|(entry_name, entry)| (entry_name.as_str(), entry)),
                );
            }
        }
    }
    if configured.get(name).copied() != Some(expected) {
        return Err("OPENCODE_MANAGED_MCP_SELECTION_MISMATCH");
    }
    if configured.into_iter().any(|(entry_name, entry)| {
        let executable = entry["command"][0]
            .as_str()
            .and_then(|path| Path::new(path).file_name());
        entry_name != name
            && entry["disabled"] != true
            && (peerwork_name(entry_name)
                || executable.is_some_and(|part| part == "peerwork" || part == "peerwork.exe")
                || entry["command"][0] == expected_executable)
    }) {
        return Err("OPENCODE_MANAGED_MCP_SELECTION_AMBIGUOUS");
    }
    let servers = servers["data"]
        .as_array()
        .ok_or("OPENCODE_MCP_CONFIGURATION_UNVERIFIED")?;
    if servers.iter().any(|entry| {
        let name_at_host = entry["name"].as_str().unwrap_or_default();
        name_at_host != name
            && entry["status"]["status"] != "disabled"
            && (peerwork_name(name_at_host) || entry["title"] == "Peerwork")
    }) {
        return Err("OPENCODE_MANAGED_MCP_SELECTION_AMBIGUOUS");
    }
    let mut selected = servers.iter().filter(|entry| entry["name"] == name);
    if selected
        .next()
        .is_none_or(|entry| entry["status"]["status"] != "connected")
        || selected.next().is_some()
    {
        return Err("OPENCODE_MANAGED_MCP_NOT_READY");
    }
    Ok(())
}

pub(crate) async fn verify_setup(
    file: PathBuf,
    directory: PathBuf,
    expected_name: String,
    expected_entry: Value,
) -> Result<()> {
    with_client(file, directory, move |client, _, directory| {
        let config = client.request("GET", &project_resource("/api/config", directory), None)?;
        let servers = client.request("GET", &project_resource("/api/mcp", directory), None)?;
        if servers["location"]["directory"] != directory {
            return Err("OPENCODE_MCP_CONFIGURATION_UNVERIFIED");
        }
        verify_entries(&config, &servers, &expected_name, &expected_entry)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_session_ownership_follows_the_exact_id_and_project() {
        let file = Path::new("/owner/opencode/service.json");
        let directory = "/owner/project";
        let selected = Target::new(file, directory, "Managed peer launch 1").unwrap();
        let another = Target::new(file, directory, "Managed peer launch 2").unwrap();
        assert_eq!(
            Target::new(file, directory, "Managed peer launch 1")
                .unwrap()
                .id,
            selected.id
        );
        assert_ne!(selected.id, another.id);
        let mut session = json!({
            "id": &selected.id,
            "title": "A later title edit",
            "location": {"directory":directory},
            "metadata": {(OWNERSHIP_KEY): &selected.ownership}
        });
        selected.verify(&session, directory).unwrap();
        assert_eq!(
            selected.verify(&session, "/other").unwrap_err(),
            "OPENCODE_MANAGED_SESSION_MISMATCH"
        );
        session["metadata"][OWNERSHIP_KEY] = json!("changed");
        assert_eq!(
            selected.verify(&session, directory).unwrap_err(),
            "OPENCODE_MANAGED_SESSION_MISMATCH"
        );
    }

    #[test]
    fn project_readback_rejects_a_different_or_additional_peerwork_entry() {
        let name = "peerwork-managed";
        let expected = json!({"type":"local","command":["/installed/peerwork", "agent", "mcp"]});
        let mut config = json!([{"type":"document","info":{"mcp":{"servers":{name:&expected}}}}]);
        let connected = json!({"data":[{"name":name,"status":{"status":"connected"}}]});
        verify_entries(&config, &connected, name, &expected).unwrap();
        config[0]["info"]["mcp"]["servers"]["lab"] =
            json!({"type":"local","command":["/other/peerwork"]});
        assert_eq!(
            verify_entries(&config, &connected, name, &expected).unwrap_err(),
            "OPENCODE_MANAGED_MCP_SELECTION_AMBIGUOUS"
        );
        config[0]["info"]["mcp"]["servers"]["lab"]["disabled"] = json!(true);
        verify_entries(&config, &connected, name, &expected).unwrap();
        config[0]["info"]["mcp"]["servers"][name]["command"][2] = json!("wrong");
        assert_eq!(
            verify_entries(&config, &connected, name, &expected).unwrap_err(),
            "OPENCODE_MANAGED_MCP_SELECTION_MISMATCH"
        );
        assert!(project_resource("/api/config", "/owner/a #")
            .contains("location%5Bdirectory%5D=%2Fowner%2Fa+%23"));
    }
}
