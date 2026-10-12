use peerwork_runtime::interrupts::InterruptMonitor;
use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
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
        _ => {
            eprintln!("{{\"code\":\"USAGE\",\"message\":\"peerwork version|capabilities|identity create PATH|identity info PATH|identity import-seed-file PATH PROTECTED_SEED_FILE|kernel open|prepare|pending|status|submit ORIGIN JOURNAL IDENTITY [COMMAND_FILE|COMMAND_ID] [--allow-loopback-http] [--authority=HEX] [--chunk-file=PATH|--chunk-stdin for prepare]; kernel migrate ORIGIN JOURNAL IDENTITY SOURCE BACKUP --trusted-signer=KEY_ID [--trusted-signer=KEY_ID ...]\"}}");
            ExitCode::FAILURE
        }
    }
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
