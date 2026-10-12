use peerwork_runtime::kernel_identity::KernelIdentity;
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
        _ => {
            eprintln!("{{\"code\":\"USAGE\",\"message\":\"peerwork version|capabilities|identity create PATH|identity info PATH\"}}");
            ExitCode::FAILURE
        }
    }
}
