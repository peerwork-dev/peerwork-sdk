//! Read-only shared user configuration selection. No identity or network side effects.
use crate::secure_state::{
    check_private_directory, missing_in_private_parent, read_private_file_bounded, SecureStateError,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

const MAX_CONFIG_BYTES: usize = 16 * 1024;
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub origin: String,
    pub state_dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<crate::transport::TransportOptions>,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("protected configuration location is unavailable or invalid")]
    Location,
    #[error("selected protected configuration is missing; no fallback was attempted")]
    Missing,
    #[error("selected configuration or state location fails protected path checks")]
    Unsafe,
    #[error("protected configuration exceeds the 16 KiB limit")]
    Limit,
    #[error("configuration must contain a valid HTTPS origin, state_dir and optional transport choices")]
    Invalid,
}
impl ConfigError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Location => "CONFIG_LOCATION",
            Self::Missing => "CONFIG_MISSING",
            Self::Unsafe => "CONFIG_UNSAFE",
            Self::Limit => "CONFIG_LIMIT",
            Self::Invalid => "CONFIG_INVALID",
        }
    }
}
fn absolute(path: &Path, base: &Path) -> Result<PathBuf, ConfigError> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut result = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => return Err(ConfigError::Unsafe),
            other => result.push(other.as_os_str()),
        }
    }
    if !result.is_absolute() {
        return Err(ConfigError::Location);
    }
    Ok(result)
}
fn selected(
    explicit: Option<&Path>,
    get: impl Fn(&str) -> Option<OsString>,
    cwd: &Path,
) -> Result<PathBuf, ConfigError> {
    if let Some(path) = explicit {
        if path.as_os_str().is_empty() {
            return Err(ConfigError::Location);
        }
        return absolute(path, cwd);
    }
    if let Some(path) = get("PEERWORK_CONFIG") {
        if path.is_empty() {
            return Err(ConfigError::Location);
        }
        return absolute(Path::new(&path), cwd);
    }
    #[cfg(target_os = "windows")]
    let path = get("APPDATA")
        .map(PathBuf::from)
        .map(|p| p.join("peerwork/config.json"));
    #[cfg(target_os = "macos")]
    let path = get("HOME")
        .map(PathBuf::from)
        .map(|p| p.join("Library/Application Support/peerwork/config.json"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let path = if let Some(xdg) = get("XDG_CONFIG_HOME") {
        Some(PathBuf::from(xdg).join("peerwork/config.json"))
    } else {
        get("HOME")
            .map(PathBuf::from)
            .map(|p| p.join(".config/peerwork/config.json"))
    };
    let path = path.ok_or(ConfigError::Location)?;
    if !path.is_absolute() {
        return Err(ConfigError::Location);
    }
    Ok(path)
}
fn read_selected(path: &Path) -> Result<ClientConfig, ConfigError> {
    if missing_in_private_parent(path) {
        return Err(ConfigError::Missing);
    }
    let bytes = read_private_file_bounded(path, MAX_CONFIG_BYTES).map_err(|e| match e {
        SecureStateError::TooLarge => ConfigError::Limit,
        _ => ConfigError::Unsafe,
    })?;
    let mut config: ClientConfig =
        serde_json::from_slice(&bytes).map_err(|_| ConfigError::Invalid)?;
    if let Some(options) = &mut config.transport {
        options.validate().map_err(|_| ConfigError::Invalid)?;
        for file in &mut options.additional_root_pem_files {
            if file.is_relative() { *file = path.parent().ok_or(ConfigError::Location)?.join(&*file); }
        }
    }
    let origin = reqwest::Url::parse(&config.origin).map_err(|_| ConfigError::Invalid)?;
    // Same HTTPS-origin predicate as HttpTransport; config discovery has no HTTP override.
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(ConfigError::Invalid);
    }
    if config.state_dir.as_os_str().is_empty() {
        return Err(ConfigError::Invalid);
    }
    config.state_dir = absolute(
        &config.state_dir,
        path.parent().ok_or(ConfigError::Location)?,
    )?;
    if config.state_dir.to_str().is_none() {
        return Err(ConfigError::Invalid);
    }
    if config.state_dir.exists() || std::fs::symlink_metadata(&config.state_dir).is_ok() {
        check_private_directory(&config.state_dir).map_err(|_| ConfigError::Unsafe)?;
    } else if !missing_in_private_parent(&config.state_dir) {
        return Err(ConfigError::Unsafe);
    }
    Ok(config)
}
/// Explicit path > PEERWORK_CONFIG > OS user-config location. Never falls back after selection.
pub fn load_config(path: Option<&Path>) -> Result<ClientConfig, ConfigError> {
    let cwd = std::env::current_dir().map_err(|_| ConfigError::Location)?;
    let selected = selected(path, |key| std::env::var_os(key), &cwd)?;
    read_selected(&selected)
}
pub fn load_config_json(path: Option<&Path>) -> String {
    let value = match load_config(path) {
        Ok(value) => serde_json::json!({"ok":true,"value":value}),
        Err(e) => serde_json::json!({"ok":false,"code":e.code(),"message":e.to_string()}),
    };
    value.to_string()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::protected_test_dir;
    fn write(path: &Path, wire: &str) {
        #[cfg(windows)]
        crate::windows_fs::create_or_check_file(path).unwrap();
        std::fs::write(path, wire).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    #[test]
    fn selection_precedence_and_no_fallback() {
        let cwd = std::env::current_dir().unwrap();
        let get = |key: &str| match key {
            "PEERWORK_CONFIG" => Some("env.json".into()),
            "HOME" => Some("/home/test".into()),
            _ => None,
        };
        assert_eq!(
            selected(Some(Path::new("explicit.json")), get, &cwd).unwrap(),
            cwd.join("explicit.json")
        );
        assert_eq!(selected(None, get, &cwd).unwrap(), cwd.join("env.json"));
        let root = protected_test_dir();
        assert_eq!(
            read_selected(&root.path().join("missing.json")),
            Err(ConfigError::Missing)
        );
    }
    #[test]
    fn relative_unicode_read_only_and_schema() {
        let root = protected_test_dir();
        let p = root.path().join("配置.json");
        write(
            &p,
            r#"{"origin":"https://control.invalid","state_dir":"用户 state"}"#,
        );
        let before = std::fs::read(&p).unwrap();
        let c = read_selected(&p).unwrap();
        assert_eq!(c.state_dir, root.path().join("用户 state"));
        assert!(!c.state_dir.exists());
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
        for wire in [
            r#"{"origin":"https://control.invalid","state_dir":"x","seed":"secret"}"#,
            r#"{"origin":"https://u:p@control.invalid","state_dir":"x"}"#,
            r#"{"origin":"https://control.invalid/path","state_dir":"x"}"#,
            r#"{"origin":"https://control.invalid/?q=1","state_dir":"x"}"#,
            r#"{"origin":"https://control.invalid/#f","state_dir":"x"}"#,
            r#"{"origin":"http://127.0.0.1","state_dir":"x"}"#,
            r#"{"origin":"https://control.invalid","state_dir":"x","state_dir":"y"}"#,
        ] {
            write(&p, wire);
            assert_eq!(read_selected(&p), Err(ConfigError::Invalid));
        }
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_files_and_state_are_refused() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = protected_test_dir();
        let p = root.path().join("config.json");
        write(
            &p,
            r#"{"origin":"https://control.invalid","state_dir":"state"}"#,
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_selected(&p), Err(ConfigError::Unsafe));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("link.json");
        symlink(&p, &link).unwrap();
        assert_eq!(read_selected(&link), Err(ConfigError::Unsafe));
        let state = root.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(read_selected(&p), Err(ConfigError::Unsafe));
        std::fs::remove_dir(state).unwrap();
        write(&p, &" ".repeat(MAX_CONFIG_BYTES + 1));
        assert_eq!(read_selected(&p), Err(ConfigError::Limit));
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    #[test]
    fn linux_defaults() {
        let cwd = Path::new("/tmp");
        assert_eq!(
            selected(
                None,
                |k| if k == "XDG_CONFIG_HOME" {
                    Some("/x".into())
                } else {
                    None
                },
                cwd
            )
            .unwrap(),
            Path::new("/x/peerwork/config.json")
        );
        assert_eq!(
            selected(
                None,
                |k| if k == "HOME" { Some("/h".into()) } else { None },
                cwd
            )
            .unwrap(),
            Path::new("/h/.config/peerwork/config.json")
        );
        assert_eq!(
            selected(
                None,
                |k| if k == "XDG_CONFIG_HOME" {
                    Some("relative".into())
                } else if k == "HOME" {
                    Some("/h".into())
                } else {
                    None
                },
                cwd
            ),
            Err(ConfigError::Location)
        );
    }
}

#[cfg(test)]
mod caller_transport_config_tests {
    use super::*;
    use crate::test_support::protected_test_dir;
    #[test]
    fn selected_transport_is_normalized_without_opening_ca_or_state() {
        let root=protected_test_dir();
        let path=root.path().join("config.json");let bytes=br#"{"origin":"https://example.invalid","state_dir":"native","transport":{"request_timeout_ms":123,"additional_root_pem_files":["public-ca.pem"]}}"#;
        #[cfg(windows)]
        crate::windows_fs::create_or_check_file(&path).unwrap();
        std::fs::write(&path,bytes).unwrap();
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap(); }
        let config=load_config(Some(&path)).unwrap();let options=config.transport.unwrap();
        assert_eq!(options.request_timeout_ms,123);assert_eq!(options.additional_root_pem_files,vec![root.path().join("public-ca.pem")]);
        assert!(!root.path().join("native").exists());assert!(!root.path().join("public-ca.pem").exists());assert_eq!(std::fs::read(path).unwrap(),bytes);
    }
}
