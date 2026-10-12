use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("version"), None) => {
            println!(
                "{}",
                serde_json::json!({"version": peerwork_core::version(), "status": "experimental"})
            );
            ExitCode::SUCCESS
        }
        (Some("capabilities"), None) => {
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
        _ => {
            eprintln!("{{\"code\":\"USAGE\",\"message\":\"peerwork version|capabilities\"}}");
            ExitCode::FAILURE
        }
    }
}
