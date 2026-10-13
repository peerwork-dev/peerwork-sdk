use peerwork_runtime::interrupts::InterruptMonitor;
use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
use peerwork_runtime::secure_action_access::{PublicActionInput, SecurePublicActionAccess};
use peerwork_runtime::secure_public_install::{
    PublicPackageInstallInput, SecurePublicPackageInstall,
};
use peerwork_runtime::secure_read_access::{SecureReadAccess, SecureReadConfig};
use peerwork_runtime::secure_read_profile::{SecureReadProfile, SecureReadProfileConfig};
use peerwork_runtime::KernelCancellationToken;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "version" => {
            println!(
                "{}",
                serde_json::json!({"version": peerwork_core::version(), "status": "experimental"})
            );
            ExitCode::SUCCESS
        }
        [command] if command == "capabilities" => {
            match serde_json::to_string(&peerwork_core::capability_manifest()) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(_) => {
                    eprintln!("{{\"code\":\"SERIALIZATION_FAILED\"}}");
                    ExitCode::FAILURE
                }
            }
        }
        [noun, verb, path] if noun == "identity" && (verb == "create" || verb == "info") => {
            let identity = if verb == "create" {
                KernelIdentity::create(Path::new(path))
            } else {
                KernelIdentity::open(Path::new(path))
            };
            match identity {
                Ok(identity) => {
                    println!(
                        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
                        identity.actor_id(),
                        identity.key_id()
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"code":"IDENTITY_STATE", "message":error.to_string()})
                    );
                    ExitCode::FAILURE
                }
            }
        }
        [noun, verb, path, seed_file] if noun == "identity" && verb == "import-seed-file" => {
            match KernelIdentity::import_seed_file(Path::new(path), Path::new(seed_file)) {
                Ok(identity) => {
                    println!(
                        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
                        identity.actor_id(),
                        identity.key_id()
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"code":"IDENTITY_STATE", "message":error.to_string()})
                    );
                    ExitCode::FAILURE
                }
            }
        }
        [noun, verb, path, pem_file] if noun == "identity" && verb == "import-legacy-pem" => {
            match KernelIdentity::import_pkcs8_pem_file(Path::new(path), Path::new(pem_file)) {
                Ok(identity) => {
                    println!(
                        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
                        identity.actor_id(),
                        identity.key_id()
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"code":"IDENTITY_STATE", "message":error.to_string()})
                    );
                    ExitCode::FAILURE
                }
            }
        }
        [noun, verb, rest @ ..] if noun == "kernel" => match kernel_command(verb, rest) {
            Ok(value) => {
                println!("{value}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!(
                    "{}",
                    serde_json::json!({"code": if InterruptMonitor::interrupted() {"INTERRUPTED"} else {"KERNEL_OPERATION"}, "message":message})
                );
                if InterruptMonitor::interrupted() {
                    ExitCode::from(130)
                } else {
                    ExitCode::FAILURE
                }
            }
        },
        [noun, verb, rest @ ..] if noun == "secure" && (verb == "read" || verb == "snapshot") => {
            let result = if verb == "read" {
                secure_read_profile_command(rest)
            } else {
                secure_read_command(rest)
            };
            match result {
                Ok(value) => {
                    println!("{value}");
                    ExitCode::SUCCESS
                }
                Err((code, message)) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"code": if InterruptMonitor::interrupted() {"INTERRUPTED"} else {code}, "message":message})
                    );
                    if InterruptMonitor::interrupted() {
                        ExitCode::from(130)
                    } else {
                        ExitCode::FAILURE
                    }
                }
            }
        }
        [noun, verb, rest @ ..]
            if noun == "secure"
                && (verb == "action-submit"
                    || verb == "action-status"
                    || verb == "action-retry"
                    || verb == "action-pending") =>
        {
            match secure_action_command(verb, rest) {
                Ok(value) => {
                    println!("{value}");
                    ExitCode::SUCCESS
                }
                Err((code, message)) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"code": if InterruptMonitor::interrupted() {"INTERRUPTED"} else {code}, "message":message})
                    );
                    if InterruptMonitor::interrupted() {
                        ExitCode::from(130)
                    } else {
                        ExitCode::FAILURE
                    }
                }
            }
        }
        [noun, verb, rest @ ..]
            if noun == "secure"
                && (verb == "install-begin"
                    || verb == "install-continue"
                    || verb == "install-pending") =>
        {
            match secure_install_command(verb, rest) {
                Ok(value) => {
                    println!("{value}");
                    ExitCode::SUCCESS
                }
                Err((code, message)) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"code": if InterruptMonitor::interrupted() {"INTERRUPTED"} else {code}, "message":message})
                    );
                    if InterruptMonitor::interrupted() {
                        ExitCode::from(130)
                    } else {
                        ExitCode::FAILURE
                    }
                }
            }
        }
        _ => {
            eprintln!("{{\"code\":\"USAGE\",\"message\":\"peerwork version|capabilities|identity create PATH|identity info PATH|identity import-legacy-pem PATH PROTECTED_PEM_FILE|identity import-seed-file PATH PROTECTED_SEED_FILE|kernel open|prepare|pending|status|submit ORIGIN JOURNAL IDENTITY [COMMAND_FILE|COMMAND_ID] [--allow-loopback-http] [--authority=HEX] [--chunk-file=PATH|--chunk-stdin for prepare]; kernel migrate ORIGIN JOURNAL IDENTITY SOURCE BACKUP --trusted-signer=KEY_ID [--trusted-signer=KEY_ID ...]; secure read --origin=URL --state-dir=DIR --identity=PATH --workspace=ID [--owner-actor=ID --owner-key=ID] [--authority=HEX]; secure snapshot ORIGIN KERNEL_JOURNAL READ_STATE LIFECYCLE IDENTITY WORKSPACE AUTHORITY OWNER_ACTOR OWNER_KEY [--allow-loopback-http] [--max-replay-artifact-bytes=N]; secure action-submit|action-status|action-retry CONFIG_JSON_FILE ACTION_JSON_FILE|COMMAND_ID; secure action-pending CONFIG_JSON_FILE; secure install-begin CONFIG_JSON_FILE INPUT_JSON_FILE | install-continue CONFIG_JSON_FILE BEGIN_COMMAND_ID | install-pending CONFIG_JSON_FILE\"}}");
            ExitCode::FAILURE
        }
    }
}

fn secure_install_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    if args.len() != if verb == "install-pending" { 1 } else { 2 } {
        return Err(("USAGE", "secure install-begin CONFIG_JSON_FILE INPUT_JSON_FILE | install-continue CONFIG_JSON_FILE BEGIN_COMMAND_ID | install-pending CONFIG_JSON_FILE".to_owned()));
    }
    let config_bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let config: SecureReadProfileConfig =
        serde_json::from_slice(&config_bytes).map_err(|e| ("CONFIG_INVALID", e.to_string()))?;
    let access = SecurePublicPackageInstall::new(config);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        (
            "INTERRUPT_HANDLER",
            "unable to install interrupt handler".to_owned(),
        )
    })?;
    match verb {
        "install-begin" => {
            let bytes = fs::read(&args[1]).map_err(|e| ("INSTALL_FILE", e.to_string()))?;
            let input: PublicPackageInstallInput = serde_json::from_slice(&bytes)
                .map_err(|e| ("INSTALL_INPUT_INVALID", e.to_string()))?;
            access.submit_begin_json_with_cancel(input, &cancel)
        }
        "install-continue" => access.continue_install_json_with_cancel(&args[1], &cancel),
        "install-pending" => access.list_pending_json_with_cancel(&cancel),
        _ => unreachable!(),
    }
    .map_err(|e| (e.code(), e.to_string()))
}

fn secure_action_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    if args.len() != if verb == "action-pending" { 1 } else { 2 } {
        return Err(("USAGE", "secure action-submit|action-status|action-retry CONFIG_JSON_FILE ACTION_JSON_FILE|COMMAND_ID; secure action-pending CONFIG_JSON_FILE".to_owned()));
    }
    let config_bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let config: SecureReadProfileConfig =
        serde_json::from_slice(&config_bytes).map_err(|e| ("CONFIG_INVALID", e.to_string()))?;
    let access = SecurePublicActionAccess::new(config);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        (
            "INTERRUPT_HANDLER",
            "unable to install interrupt handler".to_owned(),
        )
    })?;
    let result = match verb {
        "action-submit" => {
            let bytes = fs::read(&args[1]).map_err(|e| ("ACTION_FILE", e.to_string()))?;
            let input: PublicActionInput = serde_json::from_slice(&bytes)
                .map_err(|e| ("ACTION_INPUT_INVALID", e.to_string()))?;
            access.submit_new_json_with_cancel(input, &cancel)
        }
        "action-status" => access.reconcile_json_with_cancel(&args[1], &cancel),
        "action-retry" => access.retry_saved_json_with_cancel(&args[1], &cancel),
        "action-pending" => access.list_pending_json_with_cancel(&cancel),
        _ => unreachable!(),
    }
    .map_err(|e| (e.code(), e.to_string()))?;
    if verb == "action-pending" {
        return Ok(result);
    }
    // The receipt is canonical verified JSON. Embed it as a JSON value so CLI
    // consumers can inspect effect records without parsing an internal string.
    let mut envelope: serde_json::Value = serde_json::from_str(&result)
        .map_err(|_| ("RESULT_ENCODING_FAILED", "invalid action result".to_owned()))?;
    let receipt = envelope
        .get("receipt_canonical_json")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    envelope
        .as_object_mut()
        .ok_or(("RESULT_ENCODING_FAILED", "invalid result object".to_owned()))?
        .remove("receipt_canonical_json");
    let prefix = serde_json::to_string(&envelope).map_err(|_| {
        (
            "RESULT_ENCODING_FAILED",
            "result encoding failed".to_owned(),
        )
    })?;
    let receipt = receipt.unwrap_or_else(|| "null".to_owned());
    Ok(format!(
        "{},\"receipt\":{receipt}}}",
        prefix.trim_end_matches('}')
    ))
}

fn secure_read_profile_command(args: &[String]) -> Result<String, (&'static str, String)> {
    let mut origin = None;
    let mut state_dir = None;
    let mut identity_path = None;
    let mut workspace_id = None;
    let mut owner_actor_id = None;
    let mut owner_key_id = None;
    let mut authority = None;
    let mut required_features = Vec::new();
    let mut allow_loopback_http = false;
    let mut max_replay_artifact_bytes = 64 * 1024 * 1024;
    for arg in args {
        if arg == "--allow-loopback-http" {
            allow_loopback_http = true;
        } else if let Some(value) = arg.strip_prefix("--max-replay-artifact-bytes=") {
            max_replay_artifact_bytes =
                value
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| {
                        (
                            "USAGE",
                            "max replay artifact bytes must be a positive u64".to_owned(),
                        )
                    })?;
        } else if let Some(value) = arg.strip_prefix("--required-feature=") {
            required_features.push(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--origin=") {
            origin = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--state-dir=") {
            state_dir = Some(value.into());
        } else if let Some(value) = arg.strip_prefix("--identity=") {
            identity_path = Some(value.into());
        } else if let Some(value) = arg.strip_prefix("--workspace=") {
            workspace_id = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--owner-actor=") {
            owner_actor_id = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--owner-key=") {
            owner_key_id = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--authority=") {
            authority = Some(value.to_owned());
        } else {
            return Err(("USAGE", "unknown secure read option".to_owned()));
        }
    }
    let config = SecureReadProfileConfig {
        origin: origin
            .filter(|v: &String| !v.is_empty())
            .ok_or(("USAGE", "--origin is required".to_owned()))?,
        state_dir: state_dir.ok_or(("USAGE", "--state-dir is required".to_owned()))?,
        identity_path: identity_path.ok_or(("USAGE", "--identity is required".to_owned()))?,
        workspace_id: workspace_id
            .filter(|v: &String| !v.is_empty())
            .ok_or(("USAGE", "--workspace is required".to_owned()))?,
        owner_actor_id,
        owner_key_id,
        authority,
        required_features,
        allow_loopback_http,
        max_replay_artifact_bytes,
    };
    if config.owner_actor_id.is_some() != config.owner_key_id.is_some() {
        return Err((
            "USAGE",
            "owner actor and key pins must be supplied together".to_owned(),
        ));
    }
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        (
            "INTERRUPT_HANDLER",
            "unable to install interrupt handler".to_owned(),
        )
    })?;
    SecureReadProfile::new(config)
        .read_latest_json_with_cancel(&cancel)
        .map_err(|error| (error.code(), error.to_string()))
}

fn secure_read_command(args: &[String]) -> Result<String, (&'static str, String)> {
    let mut values = Vec::new();
    let mut allow_loopback_http = false;
    let mut max_replay_artifact_bytes = 64 * 1024 * 1024;
    let mut required_features = Vec::new();
    for arg in args {
        if arg == "--allow-loopback-http" {
            allow_loopback_http = true;
        } else if let Some(value) = arg.strip_prefix("--max-replay-artifact-bytes=") {
            max_replay_artifact_bytes = value
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    (
                        "USAGE",
                        "max replay artifact bytes must be a positive u64".to_owned(),
                    )
                })?;
        } else if let Some(value) = arg.strip_prefix("--required-feature=") {
            required_features.push(value.to_owned());
        } else if arg.starts_with("--") {
            return Err(("USAGE", "unknown secure read option".into()));
        } else {
            values.push(arg.as_str());
        }
    }
    if values.len() != 9 {
        return Err(("USAGE", "secure read requires origin, four protected paths and explicit workspace/authority/owner pins".into()));
    }
    let access = SecureReadAccess::new(SecureReadConfig {
        origin: values[0].to_owned(),
        kernel_journal_path: values[1].into(),
        read_state_path: values[2].into(),
        lifecycle_path: values[3].into(),
        identity_path: values[4].into(),
        workspace_id: values[5].to_owned(),
        authority: values[6].to_owned(),
        owner_actor_id: values[7].to_owned(),
        owner_key_id: values[8].to_owned(),
        required_features,
        allow_loopback_http,
        max_replay_artifact_bytes,
    });
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        (
            "INTERRUPT_HANDLER",
            "unable to install interrupt handler".to_owned(),
        )
    })?;
    access
        .read_json_with_cancel(&cancel)
        .map_err(|error| (error.code(), error.to_string()))
}

fn accepted_json(result: KernelAcceptedResult) -> serde_json::Value {
    serde_json::json!({
        "command_id": result.command_id,
        "workspace_id": result.workspace_id,
        "protocol_digest": result.protocol_digest,
        "instance_id": result.instance_id,
        "event_sequence": result.event_sequence,
        "revision": result.revision,
        "produced_record_ids": result.produced_record_ids,
        "catalog": result.catalog,
    })
}

fn kernel_command(verb: &str, args: &[String]) -> Result<serde_json::Value, String> {
    let mut args = args.to_vec();
    let mut allow_loopback = false;
    let mut authority = None;
    let mut chunk_file = None;
    let mut chunk_stdin = false;
    let mut trusted_signer_key_ids = Vec::new();
    args.retain(|argument| {
        if argument == "--allow-loopback-http" {
            allow_loopback = true;
            false
        } else if let Some(value) = argument.strip_prefix("--authority=") {
            authority = Some(value.to_owned());
            false
        } else if let Some(value) = argument.strip_prefix("--chunk-file=") {
            chunk_file = Some(value.to_owned());
            false
        } else if argument == "--chunk-stdin" {
            chunk_stdin = true;
            false
        } else if let Some(value) = argument.strip_prefix("--trusted-signer=") {
            trusted_signer_key_ids.push(value.to_owned());
            false
        } else {
            true
        }
    });
    let expected = if verb == "migrate" {
        5
    } else {
        3 + usize::from(matches!(verb, "prepare" | "status" | "submit"))
    };
    if args.len() != expected {
        return Err("kernel command requires ORIGIN JOURNAL IDENTITY and optional target".into());
    }
    if (verb == "migrate") != !trusted_signer_key_ids.is_empty() {
        return Err("trusted public signer IDs are required only for kernel migrate".into());
    }
    if chunk_file.is_some() && chunk_stdin {
        return Err("choose one upload chunk source".into());
    }
    if verb != "prepare" && (chunk_file.is_some() || chunk_stdin) {
        return Err("upload chunk is only accepted by kernel prepare".into());
    }
    let access = KernelAccess::new(&args[0], &args[1], &args[2], &[], allow_loopback)
        .with_authority(authority);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone())
        .map_err(|_| "unable to install interrupt handler")?;
    match verb {
        "open" => {
            let info = access
                .open_with_cancel(&cancel)
                .map_err(|error| error.to_string())?;
            Ok(
                serde_json::json!({"actor_id":info.actor_id,"key_id":info.key_id,"origin":info.origin}),
            )
        }
        "prepare" => {
            let metadata = fs::metadata(&args[3]).map_err(|_| "command file cannot be read")?;
            if metadata.len() > 180_000 {
                return Err("command file exceeds limit".into());
            }
            let command = fs::read(&args[3]).map_err(|_| "command file cannot be read")?;
            let chunk = if let Some(path) = chunk_file {
                let metadata = fs::metadata(&path).map_err(|_| "chunk file cannot be read")?;
                if metadata.len() > 65_536 {
                    return Err("upload chunk exceeds limit".into());
                }
                Some(fs::read(path).map_err(|_| "chunk file cannot be read")?)
            } else if chunk_stdin {
                let mut bytes = Vec::new();
                std::io::stdin()
                    .take(65_537)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "upload chunk cannot be read")?;
                Some(bytes)
            } else {
                None
            };
            if chunk.as_ref().is_some_and(|bytes| bytes.len() > 65_536) {
                return Err("upload chunk exceeds limit".into());
            }
            let pending = access
                .prepare_with_cancel(&command, chunk.as_deref(), &cancel)
                .map_err(|error| error.to_string())?;
            Ok(
                serde_json::json!({"command_id":pending.command_id,"intent_digest":pending.intent_digest,"created_at_ms":pending.created_at_ms}),
            )
        }
        "pending" => {
            let pending = access
                .pending_with_cancel(&cancel)
                .map_err(|error| error.to_string())?;
            Ok(serde_json::json!(pending.into_iter().map(|row| serde_json::json!({
                "command_id":row.command_id,"intent_digest":row.intent_digest,"created_at_ms":row.created_at_ms
            })).collect::<Vec<_>>()))
        }
        "status" => match access
            .status_with_cancel(&args[3], &cancel)
            .map_err(|error| error.to_string())?
        {
            None => Ok(serde_json::json!({"state":"NOT_FOUND"})),
            Some(KernelOperationStatus::Pending) => Ok(serde_json::json!({"state":"PENDING"})),
            Some(KernelOperationStatus::Accepted(result)) => {
                Ok(serde_json::json!({"state":"ACCEPTED","result":accepted_json(result)}))
            }
        },
        "submit" => Ok(accepted_json(
            access
                .submit_saved_with_cancel(&args[3], &cancel)
                .map_err(|error| error.to_string())?,
        )),
        "migrate" => {
            let report = access
                .migrate_ts_store(
                    Path::new(&args[3]),
                    Path::new(&args[4]),
                    &trusted_signer_key_ids,
                    &cancel,
                )
                .map_err(|error| error.to_string())?;
            Ok(
                serde_json::json!({"pending_count":report.pending_count,"accepted_count":report.accepted_count}),
            )
        }
        _ => Err("unsupported kernel operation".into()),
    }
}
