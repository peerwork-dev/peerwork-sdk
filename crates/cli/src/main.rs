use peerwork_runtime::interrupts::InterruptMonitor;
use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
use peerwork_runtime::secure_action_access::{PublicActionInput, SecurePublicActionAccess};
use peerwork_runtime::secure_public_admission::{PublicOfferInput, SecurePublicAdmission};
use peerwork_runtime::secure_public_decision::{PublicDecisionConfig, SecurePublicDecision};
use peerwork_runtime::secure_identity_directory::{IdentityDirectoryConfig, SecureIdentityDirectory};
use peerwork_runtime::secure_public_install::{
    PublicPackageInstallInput, SecurePublicPackageInstall,
};
use peerwork_runtime::secure_read_access::{SecureReadAccess, SecureReadConfig};
use peerwork_runtime::secure_read_profile::{SecureReadProfile, SecureReadProfileConfig};
use peerwork_runtime::secure_private_read_access::SecurePrivateReadAccess;
use peerwork_runtime::secure_owner_create::{
    SecureOwnerCreateConfig, SecureOwnerCreateInput, SecureOwnerWorkspaceCreate,
};
use peerwork_runtime::public_catalog::{PublicCatalog, PublicCatalogConfig};
use peerwork_runtime::secure_recipient_enrollment::{
    RecipientEnrollmentConfig, SecureRecipientEnrollment,
};
use peerwork_runtime::KernelCancellationToken;
use peerwork_core::canonical::Path as CanonicalPath;
use peerwork_core::wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue};
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
        [noun, verb, rest @ ..] if noun == "secure" && (verb == "read" || verb == "private-read" || verb == "snapshot") => {
            let result = if verb == "read" || verb == "private-read" {
                secure_read_profile_command(rest, verb == "private-read")
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
        [noun, verb, rest @ ..]
            if noun == "secure"
                && (verb == "admit-offer"
                    || verb == "admit-retry-offer"
                    || verb == "admit-pending-offers"
                    || verb == "admit-deliver"
                    || verb == "admit-retry-delivery"
                    || verb == "admit-pending-deliveries") =>
        {
            cli_result(secure_admission_command(verb, rest))
        }
        [noun, verb, rest @ ..]
            if noun == "secure"
                && (verb == "consent"
                    || verb == "consent-retry"
                    || verb == "consent-pending"
                    || verb == "receive"
                    || verb == "receive-retry"
                    || verb == "receive-pending") =>
        {
            cli_result(secure_decision_command(verb, rest))
        }
        [noun, verb, rest @ ..]
            if noun == "secure"
                && (verb == "owner-prepare"
                    || verb == "owner-create"
                    || verb == "owner-resume"
                    || verb == "owner-operations"
                    || verb == "owner-read"
                    || verb == "owner-action-submit"
                    || verb == "owner-action-status"
                    || verb == "owner-action-retry"
                    || verb == "owner-action-pending"
                    || verb == "owner-private-action-submit"
                    || verb == "owner-private-action-status"
                    || verb == "owner-private-action-retry"
                    || verb == "owner-private-action-pending"
                    || verb == "owner-install-begin"
                    || verb == "owner-install-continue"
                    || verb == "owner-install-pending"
                    || verb == "owner-admit-offer"
                    || verb == "owner-admit-retry-offer"
                    || verb == "owner-admit-pending-offers"
                    || verb == "owner-admit-deliver"
                    || verb == "owner-admit-retry-delivery"
                    || verb == "owner-admit-pending-deliveries") =>
        {
            cli_result(secure_owner_command(verb, rest))
        }
        [noun, verb, rest @ ..]
            if noun == "secure"
                && (verb == "recipient-create"
                    || verb == "recipient-publish"
                    || verb == "recipient-pending"
                    || verb == "recipient-certificate"
                    || verb == "recipient-update"
                    || verb == "recipient-retry-update"
                    || verb == "recipient-pending-updates"
                    || verb == "recipient-key-updates") =>
        {
            match secure_recipient_command(verb, rest) {
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
        [noun, verb, rest @ ..] if noun == "secure" && verb == "directory-lookup" => {
            cli_result(secure_directory_lookup(rest))
        }
        [noun, verb, rest @ ..] if noun == "secure" && (verb == "catalog-search" || verb == "catalog-inspect") => {
            cli_result(public_catalog_command(verb, rest))
        }
        _ => {
            eprintln!("{{\"code\":\"USAGE\",\"message\":\"peerwork version|capabilities|identity create PATH|identity info PATH|identity import-legacy-pem PATH PROTECTED_PEM_FILE|identity import-seed-file PATH PROTECTED_SEED_FILE|kernel open|prepare|pending|status|submit ORIGIN JOURNAL IDENTITY [COMMAND_FILE|COMMAND_ID] [--allow-loopback-http] [--authority=HEX] [--chunk-file=PATH|--chunk-stdin for prepare]; kernel migrate ORIGIN JOURNAL IDENTITY SOURCE BACKUP --trusted-signer=KEY_ID [--trusted-signer=KEY_ID ...]; secure read|private-read --origin=URL --state-dir=DIR --identity=PATH --workspace=ID [--owner-actor=ID --owner-key=ID] [--authority=HEX]; secure snapshot ORIGIN KERNEL_JOURNAL READ_STATE LIFECYCLE IDENTITY WORKSPACE AUTHORITY OWNER_ACTOR OWNER_KEY [--allow-loopback-http] [--max-replay-artifact-bytes=N]; secure action-submit|action-status|action-retry CONFIG_JSON_FILE ACTION_JSON_FILE|COMMAND_ID; secure action-pending CONFIG_JSON_FILE; secure install-begin CONFIG_JSON_FILE INPUT_JSON_FILE | install-continue CONFIG_JSON_FILE BEGIN_COMMAND_ID | install-pending CONFIG_JSON_FILE; secure owner-prepare|owner-create CONFIG_JSON_FILE INPUT_JSON_FILE | owner-resume CONFIG_JSON_FILE COMMAND_ID | owner-operations CONFIG_JSON_FILE | owner-read CONFIG_JSON_FILE WORKSPACE_ID | owner-action-submit|owner-action-status|owner-action-retry|owner-action-pending|owner-private-action-submit|owner-private-action-status|owner-private-action-retry|owner-private-action-pending|owner-install-begin|owner-install-continue|owner-install-pending|owner-admit-offer|owner-admit-retry-offer|owner-admit-pending-offers|owner-admit-deliver|owner-admit-retry-delivery|owner-admit-pending-deliveries CONFIG_JSON_FILE WORKSPACE_ID [INPUT_JSON_FILE|COMMAND_ID]; secure catalog-search CONFIG_JSON_FILE QUERY [AFTER] [LIMIT] | catalog-inspect CONFIG_JSON_FILE LOWERCASE_DIGEST; secure recipient-create|recipient-publish|recipient-pending|recipient-certificate|recipient-update|recipient-retry-update|recipient-pending-updates --origin=URL --state-dir=DIR [--mode=ROTATE|RENEW --expected-certificate-hash=HEX --update-id=ID] [--allow-loopback-http]; secure directory-lookup --origin=URL --state-dir=DIR --actor=ACTOR --key=KEY [--identity=PATH] [--allow-loopback-http]\"}}");
            ExitCode::FAILURE
        }
    }
}

fn secure_owner_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    if verb.starts_with("owner-action-") || verb.starts_with("owner-private-action-") || verb.starts_with("owner-install-") || verb.starts_with("owner-admit-") {
        return secure_owner_consumer_command(verb, args);
    }
    if args.len() != if verb == "owner-operations" { 1 } else { 2 } {
        return Err(("USAGE", "secure owner-prepare|owner-create CONFIG_JSON_FILE INPUT_JSON_FILE | owner-resume CONFIG_JSON_FILE COMMAND_ID | owner-operations CONFIG_JSON_FILE | owner-read CONFIG_JSON_FILE WORKSPACE_ID".to_owned()));
    }
    let config_bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let config: SecureOwnerCreateConfig = serde_json::from_slice(&config_bytes)
        .map_err(|_| ("CONFIG_INVALID", "invalid Owner configuration".to_owned()))?;
    let access = SecureOwnerWorkspaceCreate::new(config);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        ("INTERRUPT_HANDLER", "unable to install interrupt handler".to_owned())
    })?;
    let value = match verb {
        "owner-prepare" | "owner-create" => {
            let bytes = fs::read(&args[1]).map_err(|e| ("INPUT_FILE", e.to_string()))?;
            let input = parse_owner_input(&bytes)?;
            let result = if verb == "owner-prepare" {
                access.prepare(input, &cancel)
            } else {
                access.create(input, &cancel)
            }.map_err(|e| (e.code(), e.to_string()))?;
            serde_json::to_string(&result)
        }
        "owner-resume" => {
            let result = access.resume(&args[1], &cancel).map_err(|e| (e.code(), e.to_string()))?;
            serde_json::to_string(&result)
        }
        "owner-operations" => {
            let result = access.operations().map_err(|e| (e.code(), e.to_string()))?;
            serde_json::to_string(&result)
        }
        "owner-read" => return access.read_workspace_json(&args[1], &cancel)
            .map_err(|e| (e.code(), e.to_string())),
        _ => unreachable!(),
    };
    value.map_err(|_| ("RESULT_ENCODING_FAILED", "Owner result encoding failed".to_owned()))
}

fn secure_owner_consumer_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    let pending = verb.ends_with("-pending") || verb.ends_with("-pending-offers") || verb.ends_with("-pending-deliveries");
    if args.len() != if pending { 2 } else { 3 } {
        return Err(("USAGE", "secure owner-action-submit|owner-action-status|owner-action-retry|owner-action-pending|owner-private-action-submit|owner-private-action-status|owner-private-action-retry|owner-private-action-pending|owner-install-begin|owner-install-continue|owner-install-pending|owner-admit-offer|owner-admit-retry-offer|owner-admit-pending-offers|owner-admit-deliver|owner-admit-retry-delivery|owner-admit-pending-deliveries CONFIG_JSON_FILE WORKSPACE_ID [INPUT_JSON_FILE|COMMAND_ID]".to_owned()));
    }
    let bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let config: SecureOwnerCreateConfig = serde_json::from_slice(&bytes)
        .map_err(|_| ("CONFIG_INVALID", "invalid Owner configuration".to_owned()))?;
    let owner = SecureOwnerWorkspaceCreate::new(config);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone())
        .map_err(|_| ("INTERRUPT_HANDLER", "unable to install interrupt handler".to_owned()))?;
    let workspace_id = &args[1];
    if verb.starts_with("owner-admit-") {
        let access = owner.public_admission_access(workspace_id).map_err(|e| (e.code(), e.to_string()))?;
        let result = match verb {
            "owner-admit-offer" => {
                let bytes = fs::read(&args[2]).map_err(|e| ("OFFER_FILE", e.to_string()))?;
                let input: PublicOfferInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("ADMISSION_INPUT_INVALID", "invalid Owner offer input".to_owned()))?;
                access.submit_offer_json_with_cancel(input, &cancel)
            }
            "owner-admit-retry-offer" => access.retry_offer_json_with_cancel(&args[2], &cancel),
            "owner-admit-pending-offers" => access.pending_offers_json(),
            "owner-admit-deliver" => access.deliver_accepted_json_with_cancel(&args[2], &cancel),
            "owner-admit-retry-delivery" => access.retry_delivery_json_with_cancel(&args[2], &cancel),
            "owner-admit-pending-deliveries" => access.pending_deliveries_json(),
            _ => unreachable!(),
        };
        return result.map_err(|e| (e.code(), e.to_string()));
    }
    if verb.starts_with("owner-action-") || verb.starts_with("owner-private-action-") {
        let private = verb.starts_with("owner-private-action-");
        let suffix = if private { &verb["owner-private-action-".len()..] } else { &verb["owner-action-".len()..] };
        if private {
            let access = owner.private_action_access(workspace_id).map_err(|e| (e.code(), e.to_string()))?;
            let result = match suffix {
                "submit" => {
                    let bytes = fs::read(&args[2]).map_err(|e| ("ACTION_FILE", e.to_string()))?;
                    let input: PublicActionInput = serde_json::from_slice(&bytes)
                        .map_err(|_| ("ACTION_INPUT_INVALID", "invalid Owner action input".to_owned()))?;
                    access.submit_new_json_with_cancel(input, &cancel)
                }
                "status" => access.reconcile_json_with_cancel(&args[2], &cancel),
                "retry" => access.retry_saved_json_with_cancel(&args[2], &cancel),
                "pending" => access.list_pending_json_with_cancel(&cancel),
                _ => unreachable!(),
            };
            return result.map_err(|e| (e.code(), e.to_string()));
        }
        let access = owner.public_action_access(workspace_id).map_err(|e| (e.code(), e.to_string()))?;
        let result = match verb {
            "owner-action-submit" => {
                let bytes = fs::read(&args[2]).map_err(|e| ("ACTION_FILE", e.to_string()))?;
                let input: PublicActionInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("ACTION_INPUT_INVALID", "invalid Owner action input".to_owned()))?;
                access.submit_new_json_with_cancel(input, &cancel)
            }
            "owner-action-status" => access.reconcile_json_with_cancel(&args[2], &cancel),
            "owner-action-retry" => access.retry_saved_json_with_cancel(&args[2], &cancel),
            "owner-action-pending" => access.list_pending_json_with_cancel(&cancel),
            _ => unreachable!(),
        };
        return result.map_err(|e| (e.code(), e.to_string()));
    }
    let access = owner.public_install_access(workspace_id).map_err(|e| (e.code(), e.to_string()))?;
    let result = match verb {
        "owner-install-begin" => {
            let bytes = fs::read(&args[2]).map_err(|e| ("INSTALL_FILE", e.to_string()))?;
            let input: PublicPackageInstallInput = serde_json::from_slice(&bytes)
                .map_err(|_| ("INSTALL_INPUT_INVALID", "invalid Owner package input".to_owned()))?;
            access.submit_begin_json_with_cancel(input, &cancel)
        }
        "owner-install-continue" => access.continue_install_json_with_cancel(&args[2], &cancel),
        "owner-install-pending" => access.list_pending_json_with_cancel(&cancel),
        _ => unreachable!(),
    };
    result.map_err(|e| (e.code(), e.to_string()))
}

fn public_catalog_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    if (verb == "catalog-search" && !(2..=4).contains(&args.len()))
        || (verb == "catalog-inspect" && args.len() != 2) {
        return Err(("USAGE", "secure catalog-search CONFIG_JSON_FILE QUERY [AFTER] [LIMIT] | catalog-inspect CONFIG_JSON_FILE LOWERCASE_DIGEST".to_owned()));
    }
    let bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let config: PublicCatalogConfig = serde_json::from_slice(&bytes)
        .map_err(|_| ("CATALOG_INPUT_INVALID", "invalid catalog configuration".to_owned()))?;
    let catalog = PublicCatalog::new(config);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone())
        .map_err(|_| ("INTERRUPT_HANDLER", "unable to install interrupt handler".to_owned()))?;
    if verb == "catalog-search" {
        let limit = args.get(3).map(|value| value.parse::<u8>())
            .transpose().map_err(|_| ("CATALOG_INPUT_INVALID", "invalid catalog limit".to_owned()))?
            .unwrap_or(20);
        let result = catalog.search(&args[1], args.get(2).map(String::as_str), limit, &cancel)
            .map_err(|e| (e.code(), e.to_string()))?;
        serde_json::to_string(&result).map_err(|_| ("RESULT_ENCODING_FAILED", "catalog result encoding failed".to_owned()))
    } else {
        let result = catalog.inspect_exact(&args[1], &cancel)
            .map_err(|e| (e.code(), e.to_string()))?;
        serde_json::to_string(&result).map_err(|_| ("RESULT_ENCODING_FAILED", "catalog result encoding failed".to_owned()))
    }
}

fn parse_owner_input(bytes: &[u8]) -> Result<SecureOwnerCreateInput, (&'static str, String)> {
    if bytes.len() > 16 * 1024 {
        return Err(("INPUT_INVALID", "Owner creation input exceeds local limit".to_owned()));
    }
    let mut wire = parse_wire_json_bounded(bytes, 12, 16 * 1024)
        .map_err(|_| ("INPUT_INVALID", "invalid Owner creation JSON".to_owned()))?;
    let name_units = wire.get("name").and_then(WireValue::as_utf16)
        .ok_or(("INPUT_INVALID", "Owner name is required".to_owned()))?.to_vec();
    if String::from_utf16(&name_units).is_err() {
        let WireValue::Object(fields) = &mut wire else { unreachable!() };
        if fields.iter().any(|(key, _)| key.iter().copied().eq("name_utf16".encode_utf16())) {
            return Err(("INPUT_INVALID", "Owner name and UTF-16 sidecar conflict".to_owned()));
        }
        let (_, name) = fields.iter_mut().find(|(key, _)| key.iter().copied().eq("name".encode_utf16()))
            .ok_or(("INPUT_INVALID", "Owner name is required".to_owned()))?;
        *name = WireValue::String(Vec::new());
        fields.push(("name_utf16".encode_utf16().collect(), WireValue::Array(
            name_units.into_iter().map(|unit| WireValue::Number(f64::from(unit))).collect())));
    }
    let canonical = canonical_wire_value(&wire, CanonicalPath::SecureArtifact)
        .map_err(|_| ("INPUT_INVALID", "invalid Owner creation value".to_owned()))?;
    serde_json::from_str(&canonical)
        .map_err(|_| ("INPUT_INVALID", "invalid Owner creation input".to_owned()))
}

fn secure_recipient_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    let mut origin = None;
    let mut state_dir = None;
    let mut mode = None;
    let mut expected_certificate_hash = None;
    let mut update_id = None;
    let mut allow_loopback_http = false;
    for arg in args {
        if let Some(value) = arg.strip_prefix("--origin=") {
            origin = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--state-dir=") {
            state_dir = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--mode=") {
            mode = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--expected-certificate-hash=") {
            expected_certificate_hash = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--update-id=") {
            update_id = Some(value.to_owned());
        } else if arg == "--allow-loopback-http" {
            allow_loopback_http = true;
        } else {
            return Err(("USAGE", "unknown recipient enrollment option".to_owned()));
        }
    }
    let origin = origin
        .filter(|value: &String| !value.is_empty())
        .ok_or(("USAGE", "--origin is required".to_owned()))?;
    let state_dir = state_dir
        .filter(|value: &String| !value.is_empty())
        .ok_or(("USAGE", "--state-dir is required".to_owned()))?;
    let mut config = RecipientEnrollmentConfig::for_state_dir(origin, Path::new(&state_dir));
    config.allow_loopback_http = allow_loopback_http;
    let access = SecureRecipientEnrollment::new(config);
    if verb == "recipient-certificate" {
        return access
            .certificate_json()
            .map_err(|error| (error.code(), error.to_string()));
    }
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        (
            "INTERRUPT_HANDLER",
            "unable to install interrupt handler".to_owned(),
        )
    })?;
    if verb == "recipient-update" {
        let mode = mode.filter(|value: &String| !value.is_empty())
            .ok_or(("USAGE", "--mode is required".to_owned()))?;
        let expected = expected_certificate_hash.filter(|value: &String| !value.is_empty())
            .ok_or(("USAGE", "--expected-certificate-hash is required".to_owned()))?;
        let value = access.update_key_with_cancel(&mode, &expected, update_id.as_deref(), &cancel)
            .map_err(|error| (error.code(), error.to_string()))?;
        return serde_json::to_string(&value)
            .map_err(|_| ("RESULT_ENCODING_FAILED", "recipient update encoding failed".to_owned()));
    }
    if verb == "recipient-retry-update" {
        let update_id = update_id.filter(|value: &String| !value.is_empty())
            .ok_or(("USAGE", "--update-id is required".to_owned()))?;
        let value = access.retry_key_update_with_cancel(&update_id, &cancel)
            .map_err(|error| (error.code(), error.to_string()))?;
        return serde_json::to_string(&value)
            .map_err(|_| ("RESULT_ENCODING_FAILED", "recipient update encoding failed".to_owned()));
    }
    if verb == "recipient-pending-updates" {
        let value = access.pending_key_updates()
            .map_err(|error| (error.code(), error.to_string()))?;
        return serde_json::to_string(&value)
            .map_err(|_| ("RESULT_ENCODING_FAILED", "recipient update encoding failed".to_owned()));
    }
    if verb == "recipient-key-updates" {
        let value = access.key_updates()
            .map_err(|error| (error.code(), error.to_string()))?;
        return serde_json::to_string(&value)
            .map_err(|_| ("RESULT_ENCODING_FAILED", "recipient update encoding failed".to_owned()));
    }
    let result = match verb {
        "recipient-create" => access.create_local().map(Some),
        "recipient-publish" => access.publish_with_cancel(&cancel).map(Some),
        "recipient-pending" => access.pending(),
        _ => unreachable!(),
    }
    .map_err(|error| (error.code(), error.to_string()))?;
    serde_json::to_string(&result).map_err(|_| {
        (
            "RESULT_ENCODING_FAILED",
            "recipient result encoding failed".to_owned(),
        )
    })
}

fn secure_directory_lookup(args: &[String]) -> Result<String, (&'static str, String)> {
    let mut origin = None;
    let mut state_dir = None;
    let mut identity_path = None;
    let mut actor_id = None;
    let mut signing_key_id = None;
    let mut allow_loopback_http = false;
    for arg in args {
        if let Some(value) = arg.strip_prefix("--origin=") {
            origin = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--state-dir=") {
            state_dir = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--identity=") {
            identity_path = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--actor=") {
            actor_id = Some(value.to_owned());
        } else if let Some(value) = arg.strip_prefix("--key=") {
            signing_key_id = Some(value.to_owned());
        } else if arg == "--allow-loopback-http" {
            allow_loopback_http = true;
        } else {
            return Err(("USAGE", "unknown directory lookup option".to_owned()));
        }
    }
    let required = |value: Option<String>, flag: &'static str| {
        value.filter(|v| !v.is_empty()).ok_or(("USAGE", format!("{flag} is required")))
    };
    let origin = required(origin, "--origin")?;
    let state_dir = required(state_dir, "--state-dir")?;
    let actor_id = required(actor_id, "--actor")?;
    let signing_key_id = required(signing_key_id, "--key")?;
    let identity_path = identity_path
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(&state_dir).join("identity.state"));
    let config = IdentityDirectoryConfig {
        origin,
        identity_path,
        kernel_journal_path: Path::new(&state_dir).join("kernel.sqlite"),
        pins_path: Path::new(&state_dir).join("identity-directory.state"),
        allow_loopback_http,
    };
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone())
        .map_err(|_| ("INTERRUPT_HANDLER", "unable to install interrupt handler".to_owned()))?;
    let value = SecureIdentityDirectory::new(config)
        .lookup_certificate_with_cancel(&actor_id, &signing_key_id, &cancel)
        .map_err(|error| (error.code(), error.to_string()))?;
    serde_json::to_string(&value)
        .map_err(|_| ("RESULT_ENCODING_FAILED", "directory result encoding failed".to_owned()))
}

fn cli_result(result: Result<String, (&'static str, String)>) -> ExitCode {
    match result {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err((code, message)) => {
            eprintln!(
                "{}",
                serde_json::json!({"code": if InterruptMonitor::interrupted() { "INTERRUPTED" } else { code }, "message":message})
            );
            if InterruptMonitor::interrupted() {
                ExitCode::from(130)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn secure_admission_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    let pending = verb == "admit-pending-offers" || verb == "admit-pending-deliveries";
    if args.len() != if pending { 1 } else { 2 } {
        return Err((
            "USAGE",
            "secure admit-* PROFILE_JSON_FILE [OFFER_JSON_FILE|INVITE_ID|GRANT_ID]".to_owned(),
        ));
    }
    let bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let config: SecureReadProfileConfig =
        serde_json::from_slice(&bytes).map_err(|e| ("CONFIG_INVALID", e.to_string()))?;
    let access = SecurePublicAdmission::new(config);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        (
            "INTERRUPT_HANDLER",
            "unable to install interrupt handler".to_owned(),
        )
    })?;
    match verb {
        "admit-offer" => {
            let bytes = fs::read(&args[1]).map_err(|e| ("OFFER_FILE", e.to_string()))?;
            let input: PublicOfferInput = serde_json::from_slice(&bytes)
                .map_err(|e| ("ADMISSION_INPUT_INVALID", e.to_string()))?;
            access.submit_offer_json_with_cancel(input, &cancel)
        }
        "admit-retry-offer" => access.retry_offer_json_with_cancel(&args[1], &cancel),
        "admit-pending-offers" => access.pending_offers_json(),
        "admit-deliver" => access.deliver_accepted_json_with_cancel(&args[1], &cancel),
        "admit-retry-delivery" => access.retry_delivery_json_with_cancel(&args[1], &cancel),
        "admit-pending-deliveries" => access.pending_deliveries_json(),
        _ => unreachable!(),
    }
    .map_err(|e| (e.code(), e.to_string()))
}

fn secure_decision_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    let pending = verb == "consent-pending" || verb == "receive-pending";
    let expected = if pending {
        1
    } else if verb == "consent" {
        3
    } else {
        2
    };
    if args.len() != expected {
        return Err(("USAGE", "secure consent|consent-retry|consent-pending|receive|receive-retry|receive-pending RECIPIENT_JSON_FILE [INVITE_ID [ACCEPT|DECLINE]]".to_owned()));
    }
    let bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let mut config_value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| ("CONFIG_INVALID", e.to_string()))?;
    if config_value
        .get("authority")
        .and_then(serde_json::Value::as_str)
        == Some("")
    {
        return Err((
            "CONFIG_INVALID",
            "explicit authority must be nonempty".to_owned(),
        ));
    }
    let state_dir = config_value
        .get("state_dir")
        .and_then(serde_json::Value::as_str)
        .ok_or(("CONFIG_INVALID", "state_dir is required".to_owned()))?;
    let identity_path = Path::new(state_dir).join("identity.state");
    config_value
        .as_object_mut()
        .ok_or((
            "CONFIG_INVALID",
            "configuration must be an object".to_owned(),
        ))?
        .insert(
            "identity_path".to_owned(),
            serde_json::Value::String(identity_path.to_string_lossy().into_owned()),
        );
    config_value
        .as_object_mut()
        .expect("checked object")
        .entry("authority")
        .or_insert_with(|| serde_json::Value::String(String::new()));
    let config: PublicDecisionConfig =
        serde_json::from_value(config_value).map_err(|e| ("CONFIG_INVALID", e.to_string()))?;
    let config = config
        .resolve_default_authority()
        .map_err(|e| (e.code(), e.to_string()))?;
    let access = SecurePublicDecision::new(config);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        (
            "INTERRUPT_HANDLER",
            "unable to install interrupt handler".to_owned(),
        )
    })?;
    match verb {
        "consent" => access.decide_json_with_cancel(&args[1], &args[2], &cancel),
        "consent-retry" => access.retry_json_with_cancel(&args[1], &cancel),
        "consent-pending" => access.pending_json(),
        "receive" => access.receive_json_with_cancel(&args[1], &cancel),
        "receive-retry" => access.retry_receive_json_with_cancel(&args[1], &cancel),
        "receive-pending" => access.pending_receipts_json(),
        _ => unreachable!(),
    }
    .map_err(|e| (e.code(), e.to_string()))
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

fn secure_read_profile_command(args: &[String], private_grant: bool) -> Result<String, (&'static str, String)> {
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
    if private_grant {
        SecurePrivateReadAccess::new(config)
            .activate_and_read_json_with_cancel(&cancel)
            .map_err(|error| (error.code(), error.to_string()))
    } else {
        SecureReadProfile::new(config)
            .read_latest_json_with_cancel(&cancel)
            .map_err(|error| (error.code(), error.to_string()))
    }
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
