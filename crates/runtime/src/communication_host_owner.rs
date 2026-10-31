//! One physical session owner across independent runtime/bridge state roots.
//! These are OS-user scoped coordination locks, not a security boundary against
//! another process with the same user's full filesystem authority. Never unlink
//! a live or stale lock path: doing so could create two independent lock inodes.
use crate::secure_state::{SecureStateError, SecureStateStore};
use serde_json::{json, Value};
use std::path::PathBuf;
type R<T> = Result<T, &'static str>;

fn directory() -> R<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        // Fixed OS location, independent of HOME, TMPDIR or a caller's stateDir.
        let root = std::fs::canonicalize("/tmp").map_err(|_| "HOST_OWNER_DIRECTORY_INVALID")?;
        let path = root.join(format!("peerwork-host-owner-{}", unsafe {
            libc::geteuid()
        }));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err("HOST_OWNER_DIRECTORY_INVALID"),
        }
        let meta = std::fs::symlink_metadata(&path).map_err(|_| "HOST_OWNER_DIRECTORY_INVALID")?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.mode() & 0o077 != 0
            || meta.uid() != unsafe { libc::geteuid() }
            || std::fs::canonicalize(&path).ok().as_ref() != Some(&path)
        {
            return Err("HOST_OWNER_DIRECTORY_INVALID");
        }
        Ok(path)
    }
    #[cfg(windows)]
    {
        // The per-user Windows directory is ACL protected by the existing
        // native helper. Windows ownership/lock qualification remains separate.
        let base = std::env::var_os("LOCALAPPDATA").ok_or("HOST_OWNER_DIRECTORY_INVALID")?;
        let root = std::fs::canonicalize(PathBuf::from(base))
            .map_err(|_| "HOST_OWNER_DIRECTORY_INVALID")?;
        let path = root.join("PeerworkHostOwners");
        crate::windows_fs::create_private_directory(&path)
            .map_err(|_| "HOST_OWNER_DIRECTORY_INVALID")?;
        Ok(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err("HOST_PLATFORM_UNSUPPORTED")
    }
}

pub(crate) struct HostOwner {
    _selection: SecureStateStore,
    _session: Option<SecureStateStore>,
}
fn lock(value: &Value) -> R<SecureStateStore> {
    let id = peerwork_core::crypto::sha256_hex(value.to_string().as_bytes());
    SecureStateStore::open(&directory()?.join(format!("{id}.state"))).map_err(|e| match e {
        SecureStateError::Busy => "HOST_SESSION_ALREADY_OWNED",
        _ => "HOST_OWNER_STATE_INVALID",
    })
}
impl HostOwner {
    /// Refuse a duplicate selection before connecting to an occupied endpoint.
    pub fn select(config: &Value) -> R<Option<Self>> {
        let selection = match config["kind"].as_str() {
            Some("bridge") => return Ok(None), // The host-user bridge owns the physical session.
            Some("codex") => json!([
                "peerwork.host-selection.v1",
                "codex",
                config["endpoint"],
                config["thread_id"]
            ]),
            Some("agy-app" | "agy-stdio") => json!([
                "peerwork.host-selection.v1",
                "agy-app",
                config["conversation_id"]
            ]),
            _ => return Err("HOST_KIND_UNSUPPORTED"),
        };
        Ok(Some(Self {
            _selection: lock(&selection)?,
            _session: None,
        }))
    }
    /// The host's verified session identity closes endpoint-alias bypasses.
    /// This happens before any rendered peer input can reach the host.
    pub fn bind(&mut self, destination: &Value) -> R<()> {
        let host = destination["host"]
            .as_str()
            .ok_or("HOST_BINDING_MISMATCH")?;
        let session = destination["session_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("HOST_BINDING_MISMATCH")?;
        let conversation = destination["conversation_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("HOST_BINDING_MISMATCH")?;
        self._session = Some(lock(&json!([
            "peerwork.host-session.v1",
            host,
            session,
            conversation
        ]))?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};
    const PROBE: &str = "communication_host_owner::tests::owner_probe";

    #[test]
    fn owner_probe() {
        let Ok(config) = std::env::var("PEERWORK_HOST_OWNER_PROBE") else {
            return;
        };
        let input: Value = serde_json::from_str(&config).unwrap();
        let result = (|| {
            let mut owner = HostOwner::select(&input["config"])?.unwrap();
            owner.bind(&input["destination"])?;
            Ok::<_, &'static str>(owner)
        })();
        match result {
            Ok(_owner) => {
                println!("HOST_OWNER_PROBE_ACQUIRED");
                std::io::stdout().flush().unwrap();
                if input["hold"] == true {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).unwrap();
                }
            }
            Err(code) => println!("HOST_OWNER_PROBE_{code}"),
        }
    }
    fn command(config: &Value, destination: &Value, hold: bool) -> std::process::Command {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", PROBE, "--nocapture"]).env(
            "PEERWORK_HOST_OWNER_PROBE",
            json!({"config":config,"destination":destination,"hold":hold}).to_string(),
        );
        cmd
    }
    #[test]
    fn agy_cli_and_app_cannot_own_the_same_conversation() {
        let id = crate::communication_host::random_token().unwrap();
        let owner = HostOwner::select(&json!({"kind":"agy-app","conversation_id":id})).unwrap();
        assert!(matches!(HostOwner::select(&json!({"kind":"agy-stdio","conversation_id":id})),Err("HOST_SESSION_ALREADY_OWNED")));
        drop(owner);
        assert!(HostOwner::select(&json!({"kind":"agy-stdio","conversation_id":id})).is_ok());
    }
    #[test]
    fn session_owner_excludes_independent_processes_aliases_and_survives_crash() {
        let id = crate::communication_host::random_token().unwrap();
        let config =
            json!({"kind":"codex","endpoint":format!("ws://127.0.0.1/{id}"),"thread_id":id});
        let destination = json!({"host":"CODEX_APP_SERVER","session_id":id,"conversation_id":id});
        let mut owner = HostOwner::select(&config).unwrap().unwrap();
        owner.bind(&destination).unwrap();
        let duplicate = command(&config, &destination, false).output().unwrap();
        assert!(duplicate.status.success());
        assert!(String::from_utf8(duplicate.stdout)
            .unwrap()
            .contains("HOST_OWNER_PROBE_HOST_SESSION_ALREADY_OWNED"));
        // Different endpoint spelling cannot bypass the verified actual-session lock.
        let mut alias = config.clone();
        alias["endpoint"] = json!(format!("ws://localhost/{id}"));
        let duplicate = command(&alias, &destination, false).output().unwrap();
        assert!(duplicate.status.success());
        assert!(String::from_utf8(duplicate.stdout)
            .unwrap()
            .contains("HOST_OWNER_PROBE_HOST_SESSION_ALREADY_OWNED"));
        let other = json!({"kind":"agy-app","conversation_id":format!("other-{id}")});
        let other_destination =
            json!({"host":"ANTIGRAVITY_APP","session_id":id,"conversation_id":id});
        let independent = command(&other, &other_destination, false).output().unwrap();
        assert!(independent.status.success());
        assert!(String::from_utf8(independent.stdout)
            .unwrap()
            .contains("HOST_OWNER_PROBE_ACQUIRED"));
        drop(owner);
        let mut child = command(&config, &destination, true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut acquired = false;
        for _ in 0..4 {
            let mut line = String::new();
            assert!(output.read_line(&mut line).unwrap() > 0);
            if line.contains("HOST_OWNER_PROBE_ACQUIRED") {
                acquired = true;
                break;
            }
        }
        assert!(acquired);
        assert!(matches!(
            HostOwner::select(&config),
            Err("HOST_SESSION_ALREADY_OWNED")
        ));
        child.kill().unwrap();
        child.wait().unwrap();
        let mut recovered = HostOwner::select(&config).unwrap().unwrap();
        recovered.bind(&destination).unwrap();
        // No lease file removal or recovery of a rendered input was necessary.
    }
}
