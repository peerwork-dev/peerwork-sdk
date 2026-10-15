use peerwork_runtime::interrupts::InterruptMonitor;
use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::{KernelIdentity, KernelIdentityError};
use peerwork_runtime::secure_action_access::{PublicActionInput, SecurePublicActionAccess};
use peerwork_runtime::secure_public_admission::{PublicOfferInput, SecurePublicAdmission};
use peerwork_runtime::secure_public_decision::{PublicDecisionConfig, SecurePublicDecision};
use peerwork_runtime::secure_identity_directory::{IdentityDirectoryConfig, SecureIdentityDirectory};
use peerwork_runtime::secure_public_install::{
    PublicPackageInstallInput, SecurePublicPackageInstall,
};
use peerwork_runtime::secure_private_install::{PrivateDirectInstallBeginInput, PrivatePackageInstallBeginInput, PrivatePackageStageInput};
use peerwork_runtime::secure_read_access::{SecureReadAccess, SecureReadConfig};
use peerwork_runtime::secure_read_profile::{SecureReadProfile, SecureReadProfileConfig};
use peerwork_runtime::secure_private_read_access::SecurePrivateReadAccess;
use peerwork_runtime::secure_owner_create::{
    import_legacy_owner_identity, SecureOwnerCreateConfig, SecureOwnerCreateInput,
    SecureOwnerWorkspaceCreate,
};
use peerwork_runtime::secure_owner_attach::{HistoricalOwnerAttachInput, SecureHistoricalOwnerAttach};
use peerwork_runtime::secure_owner_format_transition::OwnerFormatTransitionInput;
use peerwork_runtime::secure_owner_coordination::OwnerCoordinationEnableInput;
use peerwork_runtime::public_catalog::{PublicCatalog, PublicCatalogConfig};
use peerwork_runtime::secure_recipient_enrollment::{
    RecipientEnrollmentConfig, SecureRecipientEnrollment,
};
use peerwork_runtime::KernelCancellationToken;
use peerwork_core::canonical::Path as CanonicalPath;
use peerwork_core::wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

// Only CLI identity arguments accept paths relative to the caller's working
// directory. The protected-state layer still checks the resulting absolute
// path's private parent, file mode, ownership, and symlink/canonical form.
fn identity_cli_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        let mut relative = PathBuf::new();
        for component in path.components() {
            if matches!(component, Component::Prefix(_)) {
                return Err("drive-relative identity paths are unsupported".to_owned());
            }
            if !matches!(component, Component::CurDir) {
                relative.push(component.as_os_str());
            }
        }
        std::env::current_dir()
            .map(|cwd| cwd.join(relative))
            .map_err(|_| "working directory is unavailable".to_owned())
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [noun, verb, rest @ ..] if noun == "config" && verb == "resolve" && rest.len() <= 1 => {
            match peerwork_runtime::protected_config::load_config(rest.first().map(Path::new)) {
                Ok(value) => { println!("{}", serde_json::to_string(&value).expect("config strings serialize")); ExitCode::SUCCESS }
                Err(error) => { eprintln!("{}",serde_json::json!({"code":error.code(),"message":error.to_string()})); ExitCode::FAILURE }
            }
        }
        [noun, verb, rest @ ..] if noun == "observations" => {
            let result = observation_command(verb, rest);
            println!("{result}");
            if serde_json::from_str::<serde_json::Value>(&result).ok()
                .is_some_and(|v|v["ok"]==true) {ExitCode::SUCCESS}else{ExitCode::FAILURE}
        }
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
            let identity = identity_cli_path(path).map_err(|error| ("IDENTITY_STATE", error)).and_then(|path| {
                if verb == "create" {
                    KernelIdentity::create(&path)
                        .map_err(|error| ("IDENTITY_STATE", error.to_string()))
                } else {
                    KernelIdentity::open(&path).map_err(|error| match error {
                        KernelIdentityError::NotFound => (error.code(), error.actionable_message()),
                        error => ("IDENTITY_STATE", error.to_string()),
                    })
                }
            });
            match identity {
                Ok(identity) => {
                    println!(
                        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
                        identity.actor_id(),
                        identity.key_id()
                    );
                    ExitCode::SUCCESS
                }
                Err((code, message)) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"code":code, "message":message})
                    );
                    ExitCode::FAILURE
                }
            }
        }
        [noun, verb, path, seed_file] if noun == "identity" && verb == "import-seed-file" => {
            let identity = identity_cli_path(path)
                .and_then(|path| identity_cli_path(seed_file).map(|seed_file| (path, seed_file)))
                .and_then(|(path, seed_file)| {
                    KernelIdentity::import_seed_file(&path, &seed_file)
                        .map_err(|error| error.to_string())
                });
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
        [noun, verb, path, pem_file] if noun == "identity" && verb == "import-legacy-pem" => {
            let identity = identity_cli_path(path)
                .and_then(|path| identity_cli_path(pem_file).map(|pem_file| (path, pem_file)))
                .and_then(|(path, pem_file)| {
                    KernelIdentity::import_pkcs8_pem_file(&path, &pem_file)
                        .map_err(|error| error.to_string())
                });
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
        [noun, verb, config_file, pem_file]
            if noun == "identity" && verb == "import-legacy-owner-pem" =>
        {
            let identity = (|| {
                let config_bytes = fs::read(config_file)
                    .map_err(|error| ("CONFIG_FILE", error.to_string()))?;
                let config: SecureOwnerCreateConfig = serde_json::from_slice(&config_bytes)
                    .map_err(|_| ("CONFIG_INVALID", "invalid Owner configuration".to_owned()))?;
                let pem_file = identity_cli_path(pem_file)
                    .map_err(|error| ("IDENTITY_STATE", error))?;
                import_legacy_owner_identity(&config, &pem_file)
                    .map_err(|error| ("IDENTITY_STATE", error.to_string()))
            })();
            match identity {
                Ok(identity) => {
                    println!(
                        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
                        identity.actor_id(),
                        identity.key_id()
                    );
                    ExitCode::SUCCESS
                }
                Err((code, message)) => {
                    eprintln!("{}", serde_json::json!({"code":code,"message":message}));
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
                    || verb == "owner-coordination-enable"
                    || verb == "owner-coordination-resume"
                    || verb == "owner-coordination-operations"
                    || verb == "owner-read"
                    || verb == "owner-attach"
                    || verb == "owner-attach-resume"
                    || verb == "owner-attach-retain"
                    || verb == "owner-attachments"
                    || verb == "owner-kernel-inspect"
                    || verb == "owner-kernel-status"
                    || verb == "owner-kernel-recover"
                    || verb == "owner-stage-inspect"
                    || verb == "owner-stage-multipart-inspect"
                    || verb == "owner-stage-multipart-attach"
                    || verb == "owner-stage-multipart-orphan-inspect"
                    || verb == "owner-stage-multipart-orphan-attach"
                    || verb == "owner-stage-recover"
                    || verb == "owner-stage-orphan-inspect"
                    || verb == "owner-stage-orphan-replan"
                    || verb == "owner-direct-begin-inspect"
                    || verb == "owner-direct-begin-attach"
                    || verb == "owner-direct-begin-recover"
                    || verb == "owner-object-intent-candidates"
                    || verb == "owner-object-intent-inspect"
                    || verb == "owner-object-intent-attach"
                    || verb == "owner-object-intent-recover"
                    || verb == "owner-object-stage-inspect"
                    || verb == "owner-object-stage-attach"
                    || verb == "owner-object-stage-recover"
                    || verb == "owner-direct-packet-inspect"
                    || verb == "owner-direct-packet-attach"
                    || verb == "owner-direct-packet-recover"
                    || verb == "owner-direct-completed-inspect"
                    || verb == "owner-direct-completed-attach"
                    || verb == "owner-format-submit"
                    || verb == "owner-format-resume"
                    || verb == "owner-format-history"
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
                    || verb == "owner-private-stage-submit"
                    || verb == "owner-private-stage-continue"
                    || verb == "owner-private-stage-list"
                    || verb == "owner-private-install-begin"
                    || verb == "owner-private-install-begin-direct"
                    || verb == "owner-private-install-continue"
                    || verb == "owner-private-install-list"
                    || verb == "owner-admit-offer"
                    || verb == "owner-admit-retry-offer"
                    || verb == "owner-admit-pending-offers"
                    || verb == "owner-admit-deliver"
                    || verb == "owner-admit-retry-delivery"
                    || verb == "owner-admit-pending-deliveries"
                    || verb == "owner-private-admit-offer"
                    || verb == "owner-private-admit-retry-offer"
                    || verb == "owner-private-admit-pending-offers"
                    || verb == "owner-private-admit-deliver"
                    || verb == "owner-private-admit-retry-delivery"
                    || verb == "owner-private-admit-pending-deliveries") =>
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
            let usage = r#"peerwork config resolve [PATH] | observations attest-external-principal|append|catalog-result|install-result|action-result|scorecard CONFIG_JSON_FILE INPUT_JSON_FILE | observations export|attestations|snapshots CONFIG_JSON_FILE; transport options on kernel/snapshot/read/private-read/recipient/directory: --request-timeout-ms=N --additional-root-pem-file=PATH (repeatable); JSON clients accept transport:{request_timeout_ms:15000,additional_root_pem_files:[]}; version|capabilities|identity create IDENTITY_STATE_FILE|identity info IDENTITY_STATE_FILE|identity import-legacy-pem IDENTITY_STATE_FILE PROTECTED_PEM_FILE|identity import-legacy-owner-pem OWNER_CONFIG_JSON_FILE PROTECTED_PEM_FILE|identity import-seed-file IDENTITY_STATE_FILE PROTECTED_SEED_FILE|kernel open|prepare|pending|status|submit ORIGIN JOURNAL IDENTITY [COMMAND_FILE|COMMAND_ID] [--allow-loopback-http] [--authority=HEX] [--chunk-file=PATH|--chunk-stdin for prepare]; kernel migrate ORIGIN JOURNAL IDENTITY SOURCE BACKUP --trusted-signer=KEY_ID [--trusted-signer=KEY_ID ...]; secure read|private-read --origin=URL --state-dir=DIR --identity=PATH --workspace=ID [--owner-actor=ID --owner-key=ID] [--authority=HEX]; secure snapshot ORIGIN KERNEL_JOURNAL READ_STATE LIFECYCLE IDENTITY WORKSPACE AUTHORITY OWNER_ACTOR OWNER_KEY [--allow-loopback-http] [--max-replay-artifact-bytes=N]; secure action-submit|action-status|action-retry CONFIG_JSON_FILE ACTION_JSON_FILE|COMMAND_ID; secure action-pending CONFIG_JSON_FILE; secure install-begin CONFIG_JSON_FILE INPUT_JSON_FILE | install-continue CONFIG_JSON_FILE BEGIN_COMMAND_ID | install-pending CONFIG_JSON_FILE; secure owner-prepare|owner-create CONFIG_JSON_FILE INPUT_JSON_FILE | owner-resume CONFIG_JSON_FILE COMMAND_ID | owner-operations CONFIG_JSON_FILE | owner-read CONFIG_JSON_FILE WORKSPACE_ID | owner-attach CONFIG_JSON_FILE INPUT_JSON_FILE | owner-attach-resume CONFIG_JSON_FILE ATTACH_ID | owner-attach-retain CONFIG_JSON_FILE ATTACH_ID EXPECTED_COMMAND_ID | owner-attachments CONFIG_JSON_FILE | owner-kernel-inspect CONFIG_JSON_FILE INPUT_JSON_FILE | owner-kernel-status CONFIG_JSON_FILE ATTACH_ID | owner-kernel-recover CONFIG_JSON_FILE ATTACH_ID COMMAND_ID | owner-stage-inspect CONFIG_JSON_FILE INPUT_JSON_FILE | owner-stage-multipart-inspect|owner-stage-multipart-attach CONFIG_JSON_FILE INPUT_JSON_FILE MATERIAL_JSON_FILE | owner-stage-recover CONFIG_JSON_FILE ATTACH_ID COMMAND_ID | owner-stage-orphan-inspect CONFIG_JSON_FILE INPUT_JSON_FILE | owner-stage-multipart-orphan-inspect|owner-stage-multipart-orphan-attach CONFIG_JSON_FILE INPUT_JSON_FILE MATERIAL_JSON_FILE | owner-stage-orphan-replan CONFIG_JSON_FILE ATTACH_ID ORIGINAL_COMMAND_ID [MATERIAL_JSON_FILE] | owner-object-stage-inspect CONFIG_JSON_FILE INPUT_JSON_FILE ORIGINAL_STAGE_COMMAND_ID OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-object-stage-attach CONFIG_JSON_FILE INPUT_JSON_FILE ORIGINAL_STAGE_COMMAND_ID INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-object-stage-recover CONFIG_JSON_FILE ATTACH_ID ORIGINAL_STAGE_COMMAND_ID | owner-object-intent-candidates CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE | owner-object-intent-inspect CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE MARKER_SHA256 OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-object-intent-attach CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE MARKER_SHA256 INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-object-intent-recover CONFIG_JSON_FILE ATTACH_ID MARKER_SHA256 | owner-direct-begin-inspect CONFIG_JSON_FILE INPUT_JSON_FILE COMMAND_ID OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-begin-attach CONFIG_JSON_FILE INPUT_JSON_FILE COMMAND_ID INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-begin-recover CONFIG_JSON_FILE ATTACH_ID COMMAND_ID | owner-direct-packet-inspect CONFIG_JSON_FILE INPUT_JSON_FILE PACKET_COMMAND_ID OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-packet-attach CONFIG_JSON_FILE INPUT_JSON_FILE PACKET_COMMAND_ID INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-packet-recover CONFIG_JSON_FILE ATTACH_ID PACKET_COMMAND_ID | owner-direct-completed-inspect CONFIG_JSON_FILE INPUT_JSON_FILE INSTANCE_ID OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-completed-attach CONFIG_JSON_FILE INPUT_JSON_FILE INSTANCE_ID INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-coordination-enable CONFIG_JSON_FILE WORKSPACE_ID INPUT_JSON_FILE | owner-coordination-resume CONFIG_JSON_FILE WORKSPACE_ID ORIGINAL_BEGIN_COMMAND_ID | owner-coordination-operations CONFIG_JSON_FILE WORKSPACE_ID | owner-format-submit CONFIG_JSON_FILE INPUT_JSON_FILE | owner-format-resume CONFIG_JSON_FILE WORKSPACE_ID COMMAND_ID | owner-format-history CONFIG_JSON_FILE WORKSPACE_ID | owner-action-submit|owner-action-status|owner-action-retry|owner-action-pending|owner-private-action-submit|owner-private-action-status|owner-private-action-retry|owner-private-action-pending|owner-install-begin|owner-install-continue|owner-install-pending|owner-private-stage-submit|owner-private-stage-continue|owner-private-stage-list|owner-private-install-begin|owner-private-install-begin-direct|owner-private-install-continue|owner-private-install-list|owner-admit-offer|owner-admit-retry-offer|owner-admit-pending-offers|owner-admit-deliver|owner-admit-retry-delivery|owner-admit-pending-deliveries|owner-private-admit-offer|owner-private-admit-retry-offer|owner-private-admit-pending-offers|owner-private-admit-deliver|owner-private-admit-retry-delivery|owner-private-admit-pending-deliveries CONFIG_JSON_FILE WORKSPACE_ID [INPUT_JSON_FILE|COMMAND_ID]; secure catalog-search CONFIG_JSON_FILE QUERY [AFTER] [LIMIT] | catalog-inspect CONFIG_JSON_FILE LOWERCASE_DIGEST; secure recipient-create|recipient-publish|recipient-pending|recipient-certificate|recipient-update|recipient-retry-update|recipient-pending-updates --origin=URL --state-dir=DIR [--mode=ROTATE|RENEW --expected-certificate-hash=HEX --update-id=ID] [--allow-loopback-http]; secure directory-lookup --origin=URL --state-dir=DIR --actor=ACTOR --key=KEY [--identity=PATH] [--allow-loopback-http]"#;
            if matches!(args.as_slice(), [command] if command == "--help" || command == "-h" || command == "help") {
                println!("{}", serde_json::json!({"status":"HELP", "usage":usage}));
                ExitCode::SUCCESS
            } else {
                eprintln!("{}", serde_json::json!({"code":"USAGE", "message":usage}));
                ExitCode::FAILURE
            }
        }
    }
}

fn secure_owner_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        if let Some(help) = owner_consumer_help(verb) {
            return Ok(help.to_string());
        }
    }
    // Generic packet aliases use the exact existing recovery dispatcher.
    let verb = match verb {
        "owner-direct-packet-inspect" => "owner-direct-begin-inspect",
        "owner-direct-packet-attach" => "owner-direct-begin-attach",
        "owner-direct-packet-recover" => "owner-direct-begin-recover",
        value => value,
    };
    if verb.starts_with("owner-action-") || verb.starts_with("owner-private-action-") || verb.starts_with("owner-install-") || verb.starts_with("owner-private-stage-") || verb.starts_with("owner-private-install-") || verb.starts_with("owner-admit-") || verb.starts_with("owner-private-admit-") {
        return secure_owner_consumer_command(verb, args);
    }
    let expected_args = match verb {
        "owner-operations" | "owner-attachments" => 1,
        "owner-coordination-enable" | "owner-coordination-resume" | "owner-format-resume" | "owner-kernel-recover" | "owner-attach-retain" | "owner-stage-recover" | "owner-stage-orphan-replan" | "owner-stage-multipart-inspect" | "owner-stage-multipart-attach" | "owner-stage-multipart-orphan-inspect" | "owner-stage-multipart-orphan-attach" | "owner-direct-begin-recover" | "owner-object-stage-recover" | "owner-object-intent-recover" => 3,
        "owner-direct-begin-inspect" | "owner-direct-completed-inspect" | "owner-object-stage-inspect" | "owner-object-intent-inspect" => 5,
        "owner-direct-begin-attach" | "owner-direct-completed-attach" | "owner-object-stage-attach" | "owner-object-intent-attach" => 6,
        _ => 2,
    };
    if args.len() != expected_args && !(verb == "owner-stage-orphan-replan" && args.len() == 4) {
        return Err(("USAGE", "secure owner-prepare|owner-create CONFIG_JSON_FILE INPUT_JSON_FILE | owner-resume CONFIG_JSON_FILE COMMAND_ID | owner-operations CONFIG_JSON_FILE | owner-read CONFIG_JSON_FILE WORKSPACE_ID | owner-attach CONFIG_JSON_FILE INPUT_JSON_FILE | owner-attach-resume CONFIG_JSON_FILE ATTACH_ID | owner-attach-retain CONFIG_JSON_FILE ATTACH_ID EXPECTED_COMMAND_ID | owner-attachments CONFIG_JSON_FILE | owner-kernel-inspect CONFIG_JSON_FILE INPUT_JSON_FILE | owner-kernel-status CONFIG_JSON_FILE ATTACH_ID | owner-kernel-recover CONFIG_JSON_FILE ATTACH_ID COMMAND_ID | owner-stage-inspect CONFIG_JSON_FILE INPUT_JSON_FILE | owner-stage-multipart-inspect|owner-stage-multipart-attach CONFIG_JSON_FILE INPUT_JSON_FILE MATERIAL_JSON_FILE | owner-stage-recover CONFIG_JSON_FILE ATTACH_ID COMMAND_ID | owner-stage-orphan-inspect CONFIG_JSON_FILE INPUT_JSON_FILE | owner-stage-multipart-orphan-inspect|owner-stage-multipart-orphan-attach CONFIG_JSON_FILE INPUT_JSON_FILE MATERIAL_JSON_FILE | owner-stage-orphan-replan CONFIG_JSON_FILE ATTACH_ID ORIGINAL_COMMAND_ID [MATERIAL_JSON_FILE] | owner-object-stage-inspect CONFIG_JSON_FILE INPUT_JSON_FILE ORIGINAL_STAGE_COMMAND_ID OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-object-stage-attach CONFIG_JSON_FILE INPUT_JSON_FILE ORIGINAL_STAGE_COMMAND_ID INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-object-stage-recover CONFIG_JSON_FILE ATTACH_ID ORIGINAL_STAGE_COMMAND_ID | owner-object-intent-candidates CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE | owner-object-intent-inspect CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE MARKER_SHA256 OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-object-intent-attach CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE MARKER_SHA256 INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-object-intent-recover CONFIG_JSON_FILE ATTACH_ID MARKER_SHA256 | owner-direct-begin-inspect CONFIG_JSON_FILE INPUT_JSON_FILE COMMAND_ID OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-begin-attach CONFIG_JSON_FILE INPUT_JSON_FILE COMMAND_ID INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-begin-recover CONFIG_JSON_FILE ATTACH_ID COMMAND_ID | owner-direct-packet-inspect CONFIG_JSON_FILE INPUT_JSON_FILE PACKET_COMMAND_ID OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-packet-attach CONFIG_JSON_FILE INPUT_JSON_FILE PACKET_COMMAND_ID INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-packet-recover CONFIG_JSON_FILE ATTACH_ID PACKET_COMMAND_ID | owner-direct-completed-inspect CONFIG_JSON_FILE INPUT_JSON_FILE INSTANCE_ID OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-direct-completed-attach CONFIG_JSON_FILE INPUT_JSON_FILE INSTANCE_ID INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE | owner-coordination-enable CONFIG_JSON_FILE WORKSPACE_ID INPUT_JSON_FILE | owner-coordination-resume CONFIG_JSON_FILE WORKSPACE_ID ORIGINAL_BEGIN_COMMAND_ID | owner-coordination-operations CONFIG_JSON_FILE WORKSPACE_ID | owner-format-submit CONFIG_JSON_FILE INPUT_JSON_FILE | owner-format-resume CONFIG_JSON_FILE WORKSPACE_ID COMMAND_ID | owner-format-history CONFIG_JSON_FILE WORKSPACE_ID".to_owned()));
    }
    let config_bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let config: SecureOwnerCreateConfig = serde_json::from_slice(&config_bytes)
        .map_err(|_| ("CONFIG_INVALID", "invalid Owner configuration".to_owned()))?;
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone()).map_err(|_| {
        ("INTERRUPT_HANDLER", "unable to install interrupt handler".to_owned())
    })?;
    if matches!(verb, "owner-kernel-inspect" | "owner-kernel-status" | "owner-kernel-recover" | "owner-stage-inspect" | "owner-stage-multipart-inspect" | "owner-stage-multipart-attach" | "owner-stage-multipart-orphan-inspect" | "owner-stage-multipart-orphan-attach" | "owner-stage-recover" | "owner-stage-orphan-inspect" | "owner-stage-orphan-replan" | "owner-direct-begin-inspect" | "owner-direct-begin-attach" | "owner-direct-begin-recover" | "owner-direct-completed-inspect" | "owner-direct-completed-attach" | "owner-object-stage-inspect" | "owner-object-stage-attach" | "owner-object-stage-recover" | "owner-object-intent-candidates" | "owner-object-intent-inspect" | "owner-object-intent-attach" | "owner-object-intent-recover") {
        let attach = SecureHistoricalOwnerAttach::new(config);
        let value = match verb {
            "owner-kernel-inspect" => {
                let bytes = fs::read(&args[1]).map_err(|_| ("INPUT_FILE", "unable to read kernel inspection input".to_owned()))?;
                let input: HistoricalOwnerAttachInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("INPUT_INVALID", "invalid kernel inspection input".to_owned()))?;
                serde_json::to_string(&attach.inspect_kernel_pending(&input, &cancel)
                    .map_err(|e| (e.code(), e.to_string()))?)
            }
            "owner-kernel-status" => serde_json::to_string(&attach.kernel_command_status(&args[1])
                .map_err(|e| (e.code(), e.to_string()))?),
            "owner-kernel-recover" => serde_json::to_string(&attach.recover_kernel_command(&args[1], &args[2], &cancel)
                .map_err(|e| (e.code(), e.to_string()))?),
            "owner-direct-begin-inspect" | "owner-direct-begin-attach" | "owner-direct-completed-inspect" | "owner-direct-completed-attach" | "owner-object-stage-inspect" | "owner-object-stage-attach" | "owner-object-intent-inspect" | "owner-object-intent-attach" => {
                let completed = verb.starts_with("owner-direct-completed-");
                let object_stage = verb.starts_with("owner-object-stage-");
                let marker_intent = verb.starts_with("owner-object-intent-");
                let bytes = fs::read(&args[1]).map_err(|_| ("INPUT_FILE", "unable to read direct install attachment input".to_owned()))?;
                let input: HistoricalOwnerAttachInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("INPUT_INVALID", "invalid direct install attachment input".to_owned()))?;
                if input.recover_pending_action || input.retain_pending_action_command_id.is_some()
                    || !input.kernel_pending_command_ids.is_empty()
                    || input.selected_pending_package_stage_command_id.is_some()
                    || input.selected_orphan_package_stage_command_id.is_some()
                    || input.expected_ts_state_digest.is_some()
                { return Err(("INPUT_INVALID", "direct install selection cannot be combined with other attachment recovery".to_owned())); }
                let selected = &args[2];
                if selected.is_empty() { return Err(("INPUT_INVALID", "selected direct instance or packet ID is required".to_owned())); }
                let (digest, options_path, material_path) = if verb.ends_with("-attach") {
                    if args[3].is_empty() { return Err(("INPUT_INVALID", "inspected TS state digest is required".to_owned())); }
                    (Some(args[3].as_str()), &args[4], &args[5])
                } else { (None, &args[3], &args[4]) };
                let options = fs::read_to_string(options_path)
                    .map_err(|_| ("INPUT_FILE", "unable to read direct install options".to_owned()))?;
                let material = fs::read_to_string(material_path)
                    .map_err(|_| ("INPUT_FILE", "unable to read direct install material".to_owned()))?;
                if options.is_empty() || material.is_empty() {
                    return Err(("INPUT_INVALID", "direct install options and material must not be empty".to_owned()));
                }
                if let Some(digest) = digest {
                    if marker_intent {
                        serde_json::to_string(&attach.attach_object_stage_intent(input, selected, digest, &options, &material, &cancel).map_err(|e| (e.code(), e.to_string()))?)
                    } else if object_stage {
                        serde_json::to_string(&attach.attach_pending_object_stage(
                            input, selected, digest, &options, &material, &cancel)
                            .map_err(|e| (e.code(), e.to_string()))?)
                    } else if completed {
                        serde_json::to_string(&attach.attach_completed_direct_install(
                            input, selected, digest, &options, &material, &cancel)
                            .map_err(|e| (e.code(), e.to_string()))?)
                    } else {
                        serde_json::to_string(&attach.attach_pending_direct_install_begin(
                            input, selected, digest, &options, &material, &cancel)
                            .map_err(|e| (e.code(), e.to_string()))?)
                    }
                } else {
                    if marker_intent {
                        serde_json::to_string(&attach.inspect_object_stage_intent(&input, selected, &options, &material, &cancel).map_err(|e| (e.code(), e.to_string()))?)
                    } else if object_stage {
                        serde_json::to_string(&attach.inspect_pending_object_stage(
                            &input, selected, &options, &material, &cancel)
                            .map_err(|e| (e.code(), e.to_string()))?)
                    } else if completed {
                        serde_json::to_string(&attach.inspect_completed_direct_install(
                            &input, selected, &options, &material, &cancel)
                            .map_err(|e| (e.code(), e.to_string()))?)
                    } else {
                        serde_json::to_string(&attach.inspect_pending_direct_install_begin(
                            &input, selected, &options, &material, &cancel)
                            .map_err(|e| (e.code(), e.to_string()))?)
                    }
                }
            },
            "owner-object-intent-candidates" => {
                let bytes=fs::read(&args[1]).map_err(|_|("INPUT_FILE","unable to read protected source selection".to_owned()))?;
                let input:HistoricalOwnerAttachInput=serde_json::from_slice(&bytes).map_err(|_|("INPUT_INVALID","invalid protected source selection".to_owned()))?;
                serde_json::to_string(&attach.object_stage_intent_candidates(&input).map_err(|e|(e.code(),e.to_string()))?)
            },
            "owner-object-intent-recover" => serde_json::to_string(&attach.recover_object_stage_intent(&args[1],&args[2],&cancel).map_err(|e|(e.code(),e.to_string()))?),
            "owner-object-stage-recover" => serde_json::to_string(&attach.recover_pending_object_stage(
                &args[1], &args[2], &cancel).map_err(|e| (e.code(), e.to_string()))?),
            "owner-direct-begin-recover" => serde_json::to_string(&attach.recover_pending_direct_install_begin(
                &args[1], &args[2], &cancel).map_err(|e| (e.code(), e.to_string()))?),
            "owner-stage-inspect" => {
                let bytes = fs::read(&args[1]).map_err(|_| ("INPUT_FILE", "unable to read package stage inspection input".to_owned()))?;
                let input: HistoricalOwnerAttachInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("INPUT_INVALID", "invalid package stage inspection input".to_owned()))?;
                serde_json::to_string(&attach.inspect_pending_package_stage(&input, &cancel)
                    .map_err(|e| (e.code(), e.to_string()))?)
            }
            "owner-stage-multipart-inspect" | "owner-stage-multipart-attach" => {
                let bytes = fs::read(&args[1]).map_err(|_| ("INPUT_FILE", "unable to read multipart stage attachment input".to_owned()))?;
                let input: HistoricalOwnerAttachInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("INPUT_INVALID", "invalid multipart stage attachment input".to_owned()))?;
                if verb == "owner-stage-multipart-inspect" {
                    if input.selected_pending_package_stage_command_id.is_some()
                        || input.selected_orphan_package_stage_command_id.is_some()
                        || input.expected_ts_state_digest.is_some()
                    {
                        return Err(("INPUT_INVALID", "multipart inspection must not select a package stage".to_owned()));
                    }
                } else if input.selected_pending_package_stage_command_id.is_none()
                    || input.selected_orphan_package_stage_command_id.is_some()
                    || input.expected_ts_state_digest.is_none()
                {
                    return Err(("INPUT_INVALID", "multipart attach requires one inspected pending command and TS state digest".to_owned()));
                }
                let material = fs::read_to_string(&args[2])
                    .map_err(|_| ("INPUT_FILE", "unable to read multipart stage material".to_owned()))?;
                if material.is_empty() { return Err(("INPUT_INVALID", "multipart stage material must not be empty".to_owned())); }
                if verb == "owner-stage-multipart-inspect" {
                    serde_json::to_string(&attach.inspect_pending_package_stage_with_material(&input, &material, &cancel)
                        .map_err(|e| (e.code(), e.to_string()))?)
                } else {
                    serde_json::to_string(&attach.attach_pending_package_stage_with_material(input, &material, &cancel)
                        .map_err(|e| (e.code(), e.to_string()))?)
                }
            },
            "owner-stage-recover" => serde_json::to_string(&attach.recover_pending_package_stage(&args[1], &args[2], &cancel)
                .map_err(|e| (e.code(), e.to_string()))?),
            "owner-stage-orphan-inspect" => {
                let bytes = fs::read(&args[1]).map_err(|_| ("INPUT_FILE", "unable to read orphan stage inspection input".to_owned()))?;
                let input: HistoricalOwnerAttachInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("INPUT_INVALID", "invalid orphan stage inspection input".to_owned()))?;
                serde_json::to_string(&attach.inspect_orphan_package_stage(&input, &cancel)
                    .map_err(|e| (e.code(), e.to_string()))?)
            },
            "owner-stage-multipart-orphan-inspect" | "owner-stage-multipart-orphan-attach" => {
                let bytes = fs::read(&args[1]).map_err(|_| ("INPUT_FILE", "unable to read multipart orphan attachment input".to_owned()))?;
                let input: HistoricalOwnerAttachInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("INPUT_INVALID", "invalid multipart orphan attachment input".to_owned()))?;
                if verb == "owner-stage-multipart-orphan-inspect" {
                    if input.selected_pending_package_stage_command_id.is_some()
                        || input.selected_orphan_package_stage_command_id.is_some()
                        || input.expected_ts_state_digest.is_some()
                    {
                        return Err(("INPUT_INVALID", "multipart orphan inspection must not select a package stage".to_owned()));
                    }
                } else if input.selected_pending_package_stage_command_id.is_some()
                    || input.selected_orphan_package_stage_command_id.is_none()
                    || input.expected_ts_state_digest.is_none()
                {
                    return Err(("INPUT_INVALID", "multipart orphan attach requires one inspected orphan command and TS state digest".to_owned()));
                }
                let material = fs::read_to_string(&args[2])
                    .map_err(|_| ("INPUT_FILE", "unable to read multipart orphan material".to_owned()))?;
                if material.is_empty() { return Err(("INPUT_INVALID", "multipart orphan material must not be empty".to_owned())); }
                if verb == "owner-stage-multipart-orphan-inspect" {
                    serde_json::to_string(&attach.inspect_multipart_orphan_package_stage_with_material(&input, &material, &cancel)
                        .map_err(|e| (e.code(), e.to_string()))?)
                } else {
                    serde_json::to_string(&attach.attach_pending_package_stage_with_material(input, &material, &cancel)
                        .map_err(|e| (e.code(), e.to_string()))?)
                }
            },
            "owner-stage-orphan-replan" => {
                let material = if let Some(path) = args.get(3) {
                    let wire = fs::read_to_string(path).map_err(|_| ("INPUT_FILE", "unable to read orphan replan material".to_owned()))?;
                    if wire.is_empty() { return Err(("INPUT_INVALID", "orphan replan material must not be empty".to_owned())); }
                    Some(wire)
                } else { None };
                serde_json::to_string(&attach.replan_orphan_package_stage(&args[1], &args[2], material.as_deref(), &cancel)
                    .map_err(|e| (e.code(), e.to_string()))?)
            },
            _ => unreachable!(),
        };
        return value.map_err(|_| ("RESULT_ENCODING_FAILED", "attachment result encoding failed".to_owned()));
    }
    if matches!(verb, "owner-attach" | "owner-attach-resume" | "owner-attach-retain" | "owner-attachments") {
        let attach = SecureHistoricalOwnerAttach::new(config);
        let value = match verb {
            "owner-attach" => {
                let bytes = fs::read(&args[1]).map_err(|_| ("INPUT_FILE", "unable to read Owner attachment input".to_owned()))?;
                let input: HistoricalOwnerAttachInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("INPUT_INVALID", "invalid Owner attachment input".to_owned()))?;
                attach.attach(input, &cancel).map_err(|e| (e.code(), e.to_string()))?
            }
            "owner-attach-resume" => attach.resume_attachment(&args[1], &cancel)
                .map_err(|e| (e.code(), e.to_string()))?,
            "owner-attach-retain" => attach.retain_pending_action(&args[1], &args[2], &cancel)
                .map_err(|e| (e.code(), e.to_string()))?,
            "owner-attachments" => return serde_json::to_string(&attach.attachments()
                .map_err(|e| (e.code(), e.to_string()))?)
                .map_err(|_| ("RESULT_ENCODING_FAILED", "attachment history encoding failed".to_owned())),
            _ => unreachable!(),
        };
        return serde_json::to_string(&value)
            .map_err(|_| ("RESULT_ENCODING_FAILED", "attachment result encoding failed".to_owned()));
    }
    if matches!(verb, "owner-coordination-enable" | "owner-coordination-resume" | "owner-coordination-operations") {
        let input: Option<OwnerCoordinationEnableInput> = if verb == "owner-coordination-enable" {
            let bytes = fs::read(&args[2]).map_err(|_| ("INPUT_FILE", "unable to read Owner coordination input".to_owned()))?;
            Some(serde_json::from_slice(&bytes)
                .map_err(|_| ("INPUT_INVALID", "invalid Owner coordination input".to_owned()))?)
        } else { None };
        let access = SecureOwnerWorkspaceCreate::new(config).coordination_access(&args[1])
            .map_err(|e| (e.code(), e.to_string()))?;
        return match verb {
            "owner-coordination-enable" => access.enable_json_with_cancel(input.expect("enable input parsed"), &cancel)
                .map_err(|e| (e.code(), e.to_string())),
            "owner-coordination-resume" => access.resume_json_with_cancel(&args[2], &cancel)
                .map_err(|e| (e.code(), e.to_string())),
            "owner-coordination-operations" => access.operations_json().map_err(|e| (e.code(), e.to_string())),
            _ => unreachable!(),
        };
    }
    if matches!(verb, "owner-format-submit" | "owner-format-resume" | "owner-format-history") {
        let input: Option<OwnerFormatTransitionInput> = if verb == "owner-format-submit" {
            let bytes = fs::read(&args[1]).map_err(|_| ("INPUT_FILE", "unable to read Owner format transition input".to_owned()))?;
            Some(serde_json::from_slice(&bytes)
                .map_err(|_| ("INPUT_INVALID", "invalid Owner format transition input".to_owned()))?)
        } else { None };
        let selected_workspace = input.as_ref().map(|value| value.workspace_id.as_str())
            .unwrap_or(&args[1]);
        let access = SecureOwnerWorkspaceCreate::new(config)
            .format_transition_access(selected_workspace)
            .map_err(|e| (e.code(), e.to_string()))?;
        return match verb {
            "owner-format-submit" => access.submit_json_with_cancel(input.expect("submit input parsed"), &cancel)
                .map_err(|e| (e.code(), e.to_string())),
            "owner-format-resume" => access.resume_json_with_cancel(&args[2], &cancel)
                .map_err(|e| (e.code(), e.to_string())),
            "owner-format-history" => access.history_json().map_err(|e| (e.code(), e.to_string())),
            _ => unreachable!(),
        };
    }
    let access = SecureOwnerWorkspaceCreate::new(config);
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

// These examples describe explicit caller choices; they never construct grants or
// convert package material into an installation request.
fn owner_consumer_help(verb: &str) -> Option<serde_json::Value> {
    if verb == "owner-create" {
        return Some(serde_json::json!({
            "command": verb,
            "usage": "secure owner-create CONFIG_JSON_FILE INPUT_JSON_FILE",
            "config_fields": ["origin", "state_dir", "allow_loopback_http (optional, explicit opt-in)", "max_replay_artifact_bytes (optional)", "max_replay_commits (optional, default 102400)", "transport (optional: request_timeout_ms, additional_root_pem_files)"],
            "input_fields": ["name", "visibility (PUBLIC or PRIVATE)", "structured (optional)", "keep_encrypted_json (optional)", "coordination_version (optional)", "name_utf16 (optional only for an unpaired-surrogate name; mutually exclusive with nonempty name)"],
            "files": "Pass local protected file paths as the two arguments. Help does not open either file or contact a service."
        }));
    }
    if verb.starts_with("owner-object-intent-") {
        return Some(serde_json::json!({"command":verb,"usage":match verb{
            "owner-object-intent-candidates"=>"secure owner-object-intent-candidates CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE",
            "owner-object-intent-inspect"=>"secure owner-object-intent-inspect CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE MARKER_SHA256 OPTIONS_JSON_FILE MATERIAL_JSON_FILE",
            "owner-object-intent-attach"=>"secure owner-object-intent-attach CONFIG_JSON_FILE SOURCE_INPUT_JSON_FILE MARKER_SHA256 INSPECTED_TS_STATE_DIGEST OPTIONS_JSON_FILE MATERIAL_JSON_FILE",
            _=>"secure owner-object-intent-recover CONFIG_JSON_FILE ATTACH_ID MARKER_SHA256"},
            "source_input_example":{"workspace_id":"<selected workspace ID>","protected_ts_state_path":"/protected/source/agent.state","protected_ts_intent_db_path":"/protected/source/workspace-intents.sqlite","protected_owner_pkcs8_path":"/protected/source/owner.pem","expected_owner_actor_id":"<selected Owner actor>","expected_owner_key_id":"<selected Owner signing key>"},
            "options_file":"Exact original install options: explicit instance_id, entrypoint, manifest/dependencies, grants and original expected_checkpoint when present. Keep the original options hash; never derive grants from package material.",
            "material_file":"Complete caller-selected {v:1,closure,bindings} material, checked against the original marker/proof/compiler output.",
            "selection":"Candidates are redacted advisory source metadata. Choose workspace/instance and exact marker_hash; inspect authenticates signed replay and returns ts_state_digest. Attach requires that digest. Optional original_command_id is provenance, never the marker selection or permission to reconstruct a packet.",
            "recovery":"After attach, use returned attach_id plus original marker hash. ATTACHED_RESTRICTED/PENDING requires explicit repeated recovery until signed END/ATTACHED; every newly authored packet is saved before POST. Marker hash is returned as object_stage_intent_marker_hash, never pending_object_stage_command_id.",
            "safety":"Protected source/PEM files remain unchanged; candidate discovery does not create an identity. Never print raw state, signed packets, keyrings or PEM contents."}));
    }
    if matches!(verb, "owner-coordination-enable" | "owner-coordination-resume" | "owner-coordination-operations") {
        return Some(serde_json::json!({
            "command": verb,
            "usage": match verb {
                "owner-coordination-enable" => "secure owner-coordination-enable CONFIG_JSON_FILE WORKSPACE_ID INPUT_JSON_FILE",
                "owner-coordination-resume" => "secure owner-coordination-resume CONFIG_JSON_FILE WORKSPACE_ID ORIGINAL_BEGIN_COMMAND_ID",
                _ => "secure owner-coordination-operations CONFIG_JSON_FILE WORKSPACE_ID",
            },
            "input_example": {"version":2,"participants":[]},
            "input_fields": "Only version (1 or 2) and participants (unique existing signed workspace-member IDs); {} defaults to v1 with omitted participants. Omitted participants uses Owner for a new installation, with no participant check when already enabled; [] explicitly requests Owner and is checked on that path too.",
            "selection": "Use a workspace from protected ordinary Owner history; PUBLIC/PRIVATE visibility is selected from that history.",
            "recovery": "Each enable/resume advances at most one persisted step. For PENDING, discover operations and resume using the original begin_command_id until signed ACCEPTED. History alone is not fresh acceptance.",
            "already_enabled": "ACCEPTED can have a null begin_command_id when no native operation was needed."
        }));
    }
    let private_install = verb.starts_with("owner-private-install-");
    let private_stage = verb.starts_with("owner-private-stage-");
    let action = verb.starts_with("owner-action-") || verb.starts_with("owner-private-action-");
    if !(private_install || private_stage || action || verb.starts_with("owner-install-")) {
        return None;
    }
    let example = match verb {
        "owner-private-install-begin-direct" => serde_json::json!({
            "closure_json":"<JSON-encoded selected package closure>",
            "expected_root_package_digest":"<compiler root package digest>",
            "expected_protocol_digest":"<compiler output protocol digest>",
            "instance_id":"<new caller-selected 43-character base64url ID>",
            "entrypoint":"<entrypoint in the selected compiled manifest>",
            "grants_json":"[{\"actor_id\":\"<authorized actor ID>\",\"actions\":[\"<selected action>\"],\"protocol_roles\":[\"<selected role>\"],\"capabilities\":[\"<selected capability>\"]}]"
        }),
        "owner-private-stage-submit" => serde_json::json!({
            "material_json":"<JSON-encoded complete selected {v:1,closure,bindings} material>",
            "expected_root_package_digest":"<compiler root package digest>",
            "expected_protocol_digest":"<compiler output protocol digest>"
        }),
        "owner-private-install-begin" => serde_json::json!({
            "stage_id":"<ACCEPTED stage ID from owner-private-stage-submit/continue>",
            "instance_id":"<new caller-selected 43-character base64url ID>",
            "entrypoint":"<selected entrypoint>",
            "grants_json":"<JSON-encoded explicit grants array>"
        }),
        "owner-private-action-submit" | "owner-action-submit" => serde_json::json!({
            "action_id":"<action in the selected installed protocol>",
            "instance_id":"<selected installed instance ID>",
            "body_json":"<JSON-encoded action body matching that action schema>"
        }),
        _ => serde_json::Value::Null,
    };
    let final_arg = if verb.ends_with("-list") || verb.ends_with("-pending") { "" }
        else if verb.ends_with("-continue") { if private_stage { " STAGE_ID" } else { " BEGIN_COMMAND_ID" } }
        else if verb.ends_with("-status") || verb.ends_with("-retry") { " COMMAND_ID" }
        else { " INPUT_JSON_FILE" };
    Some(serde_json::json!({
        "status":"HELP", "command":verb,
        "usage":format!("peerwork secure {verb} CONFIG_JSON_FILE WORKSPACE_ID{final_arg}"),
        "workspace_visibility":if private_install || private_stage || verb.starts_with("owner-private-action-") { "PRIVATE" } else { "PUBLIC" },
        "input_example":example,
        "routes":{
            "PRIVATE_install":"owner-private-install-begin-direct takes a direct envelope; alternatively owner-private-stage-submit/continue then owner-private-install-begin takes a completed stage_id. Continue with owner-private-install-continue CONFIG WORKSPACE BEGIN_COMMAND_ID; list with owner-private-install-list, stages with owner-private-stage-list.",
            "PUBLIC_install":"owner-install-begin/continue/pending are PUBLIC only. owner-install-pending accepts a WORKSPACE_ID, not a command ID; use owner-private-install-list for PRIVATE workspaces.",
            "PRIVATE_action":"owner-private-action-submit/pending/status/retry; status/retry take the original saved action COMMAND_ID.",
            "PUBLIC_action":"owner-action-submit/pending/status/retry are PUBLIC only."
        },
        "constraints":[
            "Raw {v:1,closure,bindings} material is not an install request or authorization. Select direct or staged explicitly; no automatic wrapping, source selection or grants.",
            "Expected root package digest and compiled protocol digest are distinct pins from the selected public compiler output. Same-name builtins are not interchangeable sources.",
            "grants_json is a JSON string, chosen explicitly within the caller's authority using the selected protocol's actors/actions/roles/capabilities. No grants are defaulted.",
            "Direct input optionally accepts bindings as a JSON object (not bindings_json). Direct/staged BEGIN optionally accepts disclose as [{schema,fields:[...]}]; omission differs from explicit empty. Use only reviewed disclosure choices.",
            "Optional command_id is a caller-selected 43-character base64url ID; issued_at_ms is an integer. Workspace, instance, stage and BEGIN/action command IDs are different scopes; do not substitute them.",
            "Keep package material and signing sources in protected files. Continue the saved BEGIN until ACCEPTED, then owner-read and verify the selected instance/digest and ACTIVE state. For uncertain actions inspect pending/status and retry only the saved command."
        ]
    }))
}

fn install_input_bindings(bytes: &[u8]) -> Result<Vec<u8>, (&'static str, String)> {
    let mut input: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| ("INSTALL_INPUT_INVALID", "invalid install input JSON".to_owned()))?;
    let object = input.as_object_mut().ok_or((
        "INSTALL_INPUT_INVALID", "install input must be a JSON object".to_owned(),
    ))?;
    if object.contains_key("bindings_json") {
        return Err(("INSTALL_INPUT_INVALID", "use the bindings JSON object in CLI input".to_owned()));
    }
    if object.get("disclose").is_some_and(|value| !value.is_array()) {
        return Err(("INSTALL_INPUT_INVALID", "disclose must be an array".to_owned()));
    }
    if let Some(bindings) = object.remove("bindings") {
        if !bindings.is_object() {
            return Err(("INSTALL_INPUT_INVALID", "bindings must be a JSON object".to_owned()));
        }
        object.insert("bindings_json".into(), serde_json::Value::String(bindings.to_string()));
    }
    serde_json::to_vec(&input)
        .map_err(|_| ("INSTALL_INPUT_INVALID", "install input encoding failed".to_owned()))
}

fn secure_owner_consumer_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    let pending = verb.ends_with("-pending") || verb.ends_with("-pending-offers") || verb.ends_with("-pending-deliveries") || verb == "owner-private-stage-list" || verb == "owner-private-install-list";
    if args.len() != if pending { 2 } else { 3 } {
        return Err(("USAGE", "secure owner-action-submit|owner-action-status|owner-action-retry|owner-action-pending|owner-private-action-submit|owner-private-action-status|owner-private-action-retry|owner-private-action-pending|owner-install-begin|owner-install-continue|owner-install-pending|owner-private-stage-submit|owner-private-stage-continue|owner-private-stage-list|owner-private-install-begin|owner-private-install-begin-direct|owner-private-install-continue|owner-private-install-list|owner-admit-offer|owner-admit-retry-offer|owner-admit-pending-offers|owner-admit-deliver|owner-admit-retry-delivery|owner-admit-pending-deliveries|owner-private-admit-offer|owner-private-admit-retry-offer|owner-private-admit-pending-offers|owner-private-admit-deliver|owner-private-admit-retry-delivery|owner-private-admit-pending-deliveries CONFIG_JSON_FILE WORKSPACE_ID [INPUT_JSON_FILE|COMMAND_ID]".to_owned()));
    }
    let bytes = fs::read(&args[0]).map_err(|e| ("CONFIG_FILE", e.to_string()))?;
    let config: SecureOwnerCreateConfig = serde_json::from_slice(&bytes)
        .map_err(|_| ("CONFIG_INVALID", "invalid Owner configuration".to_owned()))?;
    let owner = SecureOwnerWorkspaceCreate::new(config);
    let cancel = KernelCancellationToken::new();
    let _interrupts = InterruptMonitor::start(cancel.clone())
        .map_err(|_| ("INTERRUPT_HANDLER", "unable to install interrupt handler".to_owned()))?;
    let workspace_id = &args[1];
    if verb.starts_with("owner-private-stage-") {
        let access = owner.private_install_access(workspace_id).map_err(|e| (e.code(), e.to_string()))?;
        let result = match verb {
            "owner-private-stage-submit" => {
                let bytes = fs::read(&args[2]).map_err(|e| ("STAGE_FILE", e.to_string()))?;
                let input: PrivatePackageStageInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("INSTALL_INPUT_INVALID", "PRIVATE stage-submit requires material_json plus expected_root_package_digest and expected_protocol_digest; raw material is not an envelope. Run secure owner-private-stage-submit --help".to_owned()))?;
                access.stage_package_json_with_cancel(input, &cancel)
            }
            "owner-private-stage-continue" => access.continue_stage_json_with_cancel(&args[2], &cancel),
            "owner-private-stage-list" => access.stages_json(),
            _ => unreachable!(),
        };
        return result.map_err(|e| (e.code(), e.to_string()));
    }
    if verb.starts_with("owner-private-install-") {
        let access = owner.private_install_access(workspace_id).map_err(|e| (e.code(), e.to_string()))?;
        let result = match verb {
            "owner-private-install-begin" => {
                let bytes = fs::read(&args[2]).map_err(|e| ("INSTALL_FILE", e.to_string()))?;
                let normalized = install_input_bindings(&bytes)?;
                let input: PrivatePackageInstallBeginInput = serde_json::from_slice(&normalized)
                    .map_err(|_| ("INSTALL_INPUT_INVALID", "PRIVATE install-begin requires an ACCEPTED stage_id, instance_id, entrypoint and explicit grants_json. For a selected closure use owner-private-install-begin-direct. Raw material is not authorization. Run secure owner-private-install-begin --help".to_owned()))?;
                access.submit_begin_json_with_cancel(input, &cancel)
            }
            "owner-private-install-begin-direct" => {
                let bytes = fs::read(&args[2]).map_err(|e| ("INSTALL_FILE", e.to_string()))?;
                let normalized = install_input_bindings(&bytes)?;
                let input: PrivateDirectInstallBeginInput = serde_json::from_slice(&normalized)
                    .map_err(|_| ("INSTALL_INPUT_INVALID", "PRIVATE direct install requires closure_json, expected_root_package_digest, expected_protocol_digest, instance_id, entrypoint and explicit grants_json; raw material is not an install envelope. Run secure owner-private-install-begin-direct --help".to_owned()))?;
                access.submit_direct_begin_json_with_cancel(input, &cancel)
            }
            "owner-private-install-continue" => access.continue_install_json_with_cancel(&args[2], &cancel),
            "owner-private-install-list" => access.installs_json(),
            _ => unreachable!(),
        };
        return result.map_err(|e| (e.code(), e.to_string()));
    }
    if verb.starts_with("owner-private-admit-") {
        let access = owner.private_admission_access(workspace_id).map_err(|e| (e.code(), e.to_string()))?;
        let result = match verb {
            "owner-private-admit-offer" => {
                let bytes = fs::read(&args[2]).map_err(|e| ("OFFER_FILE", e.to_string()))?;
                let input: PublicOfferInput = serde_json::from_slice(&bytes)
                    .map_err(|_| ("ADMISSION_INPUT_INVALID", "invalid Owner offer input".to_owned()))?;
                access.submit_offer_json_with_cancel(input, &cancel)
            }
            "owner-private-admit-retry-offer" => access.retry_offer_json_with_cancel(&args[2], &cancel),
            "owner-private-admit-pending-offers" => access.pending_offers_json(),
            "owner-private-admit-deliver" => access.deliver_accepted_json_with_cancel(&args[2], &cancel),
            "owner-private-admit-retry-delivery" => access.retry_delivery_json_with_cancel(&args[2], &cancel),
            "owner-private-admit-pending-deliveries" => access.pending_deliveries_json(),
            _ => unreachable!(),
        };
        return result.map_err(|e| (e.code(), e.to_string()));
    }
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
            let result = result.map_err(|e| (e.code(), e.to_string()))?;
            return if suffix == "pending" { Ok(result) } else { action_result_with_receipt(result) };
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
        let result = result.map_err(|e| (e.code(), e.to_string()))?;
        return if verb == "owner-action-pending" { Ok(result) } else { action_result_with_receipt(result) };
    }
    let access = owner.public_install_access(workspace_id).map_err(|e| (e.code(), format!("{e}; owner-install-* is PUBLIC only. For a PRIVATE workspace use owner-private-install-list and owner-private-install-begin-direct or the explicit staged route; run secure owner-private-install-begin-direct --help")))?;
    let result = match verb {
        "owner-install-begin" => {
            let bytes = fs::read(&args[2]).map_err(|e| ("INSTALL_FILE", e.to_string()))?;
            let normalized = install_input_bindings(&bytes)?;
            let input: PublicPackageInstallInput = serde_json::from_slice(&normalized)
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

fn transport_arguments(args: &[String]) -> Result<(Vec<String>, peerwork_runtime::transport::TransportOptions), (&'static str, String)> {
    let mut options = peerwork_runtime::transport::TransportOptions::default(); let mut rest = Vec::new();
    for arg in args {
        if let Some(value) = arg.strip_prefix("--request-timeout-ms=") {
            options.request_timeout_ms = value.parse().map_err(|_| ("CONFIG_INVALID", "invalid transport options".to_owned()))?;
        } else if let Some(value) = arg.strip_prefix("--additional-root-pem-file=") {
            options.additional_root_pem_files.push(value.into());
        } else { rest.push(arg.clone()); }
    }
    options.validate().map_err(|_| ("CONFIG_INVALID", "invalid transport options".to_owned()))?;
    Ok((rest, options))
}

fn secure_recipient_command(verb: &str, args: &[String]) -> Result<String, (&'static str, String)> {
    let (filtered, transport) = transport_arguments(args)?; let args = filtered.as_slice();
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
    config.transport = transport;
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
    let (filtered, transport) = transport_arguments(args)?; let args = filtered.as_slice();
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
            transport: transport.clone(),
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
            let normalized = install_input_bindings(&bytes)?;
            let input: PublicPackageInstallInput = serde_json::from_slice(&normalized)
                .map_err(|e| ("INSTALL_INPUT_INVALID", e.to_string()))?;
            access.submit_begin_json_with_cancel(input, &cancel)
        }
        "install-continue" => access.continue_install_json_with_cancel(&args[1], &cancel),
        "install-pending" => access.list_pending_json_with_cancel(&cancel),
        _ => unreachable!(),
    }
    .map_err(|e| (e.code(), e.to_string()))
}

fn action_result_with_receipt(result: String) -> Result<String, (&'static str, String)> {
    let mut envelope: serde_json::Value = serde_json::from_str(&result)
        .map_err(|_| ("RESULT_ENCODING_FAILED", "invalid action result".to_owned()))?;
    let object = envelope.as_object_mut()
        .ok_or(("RESULT_ENCODING_FAILED", "invalid result object".to_owned()))?;
    let status = object.get("status").and_then(serde_json::Value::as_str)
        .ok_or(("RESULT_ENCODING_FAILED", "invalid action status".to_owned()))?
        .to_owned();
    let receipt = match (status.as_str(), object.remove("receipt_canonical_json")) {
        ("PENDING", None | Some(serde_json::Value::Null)) => serde_json::Value::Null,
        ("ACCEPTED", Some(serde_json::Value::String(wire))) => {
            let value: serde_json::Value = serde_json::from_str(&wire)
                .map_err(|_| ("RESULT_ENCODING_FAILED", "invalid verified receipt".to_owned()))?;
            if !value.is_object() {
                return Err(("RESULT_ENCODING_FAILED", "invalid verified receipt".to_owned()));
            }
            value
        }
        _ => return Err(("RESULT_ENCODING_FAILED", "missing verified receipt".to_owned())),
    };
    object.insert("receipt".to_owned(), receipt);
    serde_json::to_string(&envelope)
        .map_err(|_| ("RESULT_ENCODING_FAILED", "result encoding failed".to_owned()))
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
    // Both standalone and Owner action verbs expose the verified receipt as
    // a JSON value, not as the runtime's internal canonical JSON string.
    action_result_with_receipt(result)
}

fn secure_read_profile_command(args: &[String], private_grant: bool) -> Result<String, (&'static str, String)> {
    let (filtered, transport) = transport_arguments(args)?; let args = filtered.as_slice();
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
    let mut max_replay_commits = 102_400;
    for arg in args {
        if arg == "--allow-loopback-http" {
            allow_loopback_http = true;
        } else if let Some(value) = arg.strip_prefix("--max-replay-commits=") {
            max_replay_commits = value.parse::<u64>().ok().filter(|n| *n > 0 && usize::try_from(*n).is_ok()).ok_or(("USAGE", "max replay commits must be positive and fit this platform".to_owned()))?;
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
            transport: transport.clone(),
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
        max_replay_commits,
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
    let (filtered, transport) = transport_arguments(args)?; let args = filtered.as_slice();
    let mut values = Vec::new();
    let mut allow_loopback_http = false;
    let mut max_replay_artifact_bytes = 64 * 1024 * 1024;
    let mut max_replay_commits = 102_400;
    let mut required_features = Vec::new();
    for arg in args {
        if arg == "--allow-loopback-http" {
            allow_loopback_http = true;
        } else if let Some(value) = arg.strip_prefix("--max-replay-commits=") {
            max_replay_commits = value.parse::<u64>().ok().filter(|n| *n > 0 && usize::try_from(*n).is_ok()).ok_or(("USAGE", "max replay commits must be positive and fit this platform".to_owned()))?;
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
            transport: transport.clone(),
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
        max_replay_commits,
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
    let (mut args, transport) = transport_arguments(args).map_err(|(_, message)| message)?;
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
        .with_authority(authority).with_transport_options(transport);
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

// Bound reads before JSON parsing; neither paths nor file contents enter errors.
fn observation_command(verb:&str,args:&[String])->String {
    fn read(path:&str,limit:u64)->Result<String,()> {
        let file=fs::File::open(path).map_err(|_|())?;
        let mut bytes=Vec::new();
        file.take(limit+1).read_to_end(&mut bytes).map_err(|_|())?;
        if bytes.len() as u64>limit{return Err(())}
        String::from_utf8(bytes).map_err(|_|())
    }
    let operation=match verb {
        "attest-external-principal"=>"attest_external_principal", "catalog-result"=>"catalog_result", "install-result"=>"install_result",
        "action-result"=>"action_result",other=>other,
    };
    let result=(||{
        let no_input=matches!(operation,"export"|"attestations"|"snapshots");
        if args.len()!=if no_input{1}else{2}
            || !matches!(operation,"append"|"attest_external_principal"|"attestations"|"catalog_result"|"install_result"|"action_result"|"scorecard"|"export"|"snapshots") {return Err(())}
        let config=read(&args[0],8192)?;
        let input=if no_input{None}else{Some(read(&args[1],8*1024*1024)?)};
        Ok(peerwork_runtime::acquisition::acquisition_json(operation,&config,input.as_deref()))
    })();
    result.unwrap_or_else(|()|serde_json::json!({"ok":false,"code":"OBSERVATION_INPUT_INVALID","message":"invalid observation input"}).to_string())
}
