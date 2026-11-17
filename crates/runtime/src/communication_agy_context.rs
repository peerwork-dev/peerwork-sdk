//! Refreshable launch context for the originally selected AGY App host.
//! Only explicit host registration writes it; dispatch never scans processes.
use crate::secure_state::{SecureStateError, SecureStateStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

type R<T> = Result<T, &'static str>;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    conversation_id: String,
    agentapi_path: String,
    address: String,
    token: String,
}
fn path(config: &Value) -> R<Option<PathBuf>> {
    let Some(directory) = config.get("inbox_directory") else { return Ok(None) };
    let directory = directory.as_str().filter(|s| Path::new(s).is_absolute())
        .ok_or("AGY_HOST_ENVIRONMENT_INVALID")?;
    let conversation = super::text(config, "conversation_id")?;
    Ok(Some(Path::new(directory).join(format!("agy-host-{}.state",
        peerwork_core::crypto::sha256_hex(conversation.as_bytes())))))
}
fn validate(context: &Context, config: &Value) -> R<()> {
    if context.conversation_id != config["conversation_id"] || context.agentapi_path != config["agentapi_path"]
        || context.address.len() > 256 || context.token.is_empty() || context.token.len() > 4096
        || context.token.chars().any(char::is_control)
    { return Err("AGY_HOST_ENVIRONMENT_INVALID") }
    let url = reqwest::Url::parse(&format!("http://{}", context.address))
        .map_err(|_| "AGY_HOST_ENVIRONMENT_INVALID")?;
    if !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
        || url.port().is_none_or(|port| port == 0) || url.path() != "/"
        || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some()
    { return Err("AGY_HOST_ENVIRONMENT_INVALID") }
    Ok(())
}
fn save(config: &Value, address: &str, token: &str) -> R<bool> {
    let Some(path) = path(config)? else { return Ok(false) };
    let context = Context { conversation_id: super::text(config, "conversation_id")?.into(),
        agentapi_path: super::text(config, "agentapi_path")?.into(), address: address.into(), token: token.into() };
    validate(&context, config)?;
    let state = SecureStateStore::open(&path).map_err(|_| "AGY_HOST_ENVIRONMENT_UNAVAILABLE")?;
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&context).map_err(|_| "AGY_HOST_ENVIRONMENT_INVALID")?);
    state.write_exact(&encoded).map_err(|_| "AGY_HOST_ENVIRONMENT_UNAVAILABLE")?;
    Ok(true)
}
pub(super) fn capture(config: &Value) -> R<bool> {
    if config["kind"] != "agy-app" || path(config)?.is_none() { return Ok(false) }
    match (std::env::var("ANTIGRAVITY_LS_ADDRESS"), std::env::var("ANTIGRAVITY_CSRF_TOKEN")) {
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => Ok(false),
        (Ok(address), Ok(token)) => save(config, &address, &token),
        _ => Err("AGY_HOST_ENVIRONMENT_INVALID"),
    }
}
pub(super) fn configure(command: &mut std::process::Command, config: &Value) -> R<()> {
    let Some(path) = path(config)? else { return Ok(()) };
    let bytes = match SecureStateStore::read_snapshot(&path, 8192) {
        Ok(bytes) => zeroize::Zeroizing::new(bytes),
        Err(SecureStateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("AGY_HOST_ENVIRONMENT_UNAVAILABLE"),
    };
    let context: Context = serde_json::from_slice(&bytes).map_err(|_| "AGY_HOST_ENVIRONMENT_INVALID")?;
    validate(&context, config)?;
    command.env("ANTIGRAVITY_LS_ADDRESS", context.address).env("ANTIGRAVITY_CSRF_TOKEN", context.token);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn config(directory: &Path) -> Value {
        json!({"kind":"agy-app", "conversation_id":"original", "agentapi_path":"/synthetic/agentapi", "inbox_directory":directory})
    }
    #[test]
    fn original_host_refresh_overrides_stale_resident_environment_without_rebinding() {
        let root = crate::test_support::protected_test_dir();
        let config = config(root.path());
        for (address, token) in [("localhost:33729", "old-secret"), ("localhost:44713", "new-secret")] {
            assert!(save(&config, address, token).unwrap());
            let mut command = std::process::Command::new("/synthetic/agentapi");
            command.env("ANTIGRAVITY_LS_ADDRESS", "localhost:1").env("ANTIGRAVITY_CSRF_TOKEN", "stale");
            configure(&mut command, &config).unwrap();
            let values = command.get_envs().map(|(k,v)|(k.to_str().unwrap(),v.unwrap().to_str().unwrap())).collect::<std::collections::BTreeMap<_,_>>();
            assert_eq!(values["ANTIGRAVITY_LS_ADDRESS"], address);
            assert_eq!(values["ANTIGRAVITY_CSRF_TOKEN"], token);
        }
        let mut changed = config.clone(); changed["agentapi_path"] = json!("/other/agentapi");
        assert_eq!(configure(&mut std::process::Command::new("ignored"), &changed), Err("AGY_HOST_ENVIRONMENT_INVALID"));
    }
    #[test]
    fn invalid_refresh_preserves_last_good_context_and_optional_legacy_launch() {
        let root = crate::test_support::protected_test_dir(); let config = config(root.path());
        assert!(configure(&mut std::process::Command::new("ignored"), &config).is_ok());
        save(&config, "localhost:1234", "secret").unwrap();
        let original = SecureStateStore::read_snapshot(&path(&config).unwrap().unwrap(), 8192).unwrap();
        for (address, token) in [("remote.invalid:1234", "secret"), ("localhost:1234/path", "secret"), ("localhost:1234", "\nsecret")] {
            assert_eq!(save(&config, address, token), Err("AGY_HOST_ENVIRONMENT_INVALID"));
        }
        assert_eq!(SecureStateStore::read_snapshot(&path(&config).unwrap().unwrap(), 8192).unwrap(), original);
        assert!(configure(&mut std::process::Command::new("ignored"), &json!({"conversation_id":"original"})).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn resident_app_adapter_reads_refreshed_context_before_each_compact_send() {
        use std::os::unix::fs::PermissionsExt;
        let root=crate::test_support::protected_test_dir();
        let exe=root.path().join("agentapi");let captured=root.path().join("captured");
        std::fs::write(&exe,format!("#!/usr/bin/python3\nimport os,json,sys\nassert sys.argv[1:3]==['send-message','original']\nwith open({},'a') as output: output.write(json.dumps([os.environ['ANTIGRAVITY_LS_ADDRESS'],os.environ['ANTIGRAVITY_CSRF_TOKEN']])+'\\n')\n",serde_json::to_string(captured.to_str().unwrap()).unwrap())).unwrap();
        std::fs::set_permissions(&exe,std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config=config(root.path());config["agentapi_path"]=json!(exe);
        save(&config,"localhost:1234","old-token").unwrap();
        let runtime=tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let mut host=super::super::Host::open(config.clone(),runtime.handle().clone()).unwrap();
        for (address,token) in [("localhost:1234","old-token"),("localhost:4321","new-token")] {
            save(&config,address,token).unwrap();
            let message=json!({"format":"peerwork.notification-frame.v1","batch":"B".repeat(43),"message_id":address});
            let receipt=host.deliver(&json!({}),&message).unwrap();
            assert_eq!(receipt["state"],"HOST_QUEUED");assert_eq!(receipt["model_response"],"NOT_ATTESTED");
        }
        let observed=std::fs::read_to_string(captured).unwrap();
        assert_eq!(observed.lines().map(|line|serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>(),vec![json!(["localhost:1234","old-token"]),json!(["localhost:4321","new-token"])]);
        assert_eq!(host.destination["conversation_id"],"original");
    }
}
