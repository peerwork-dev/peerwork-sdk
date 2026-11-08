//! Unreleased program SDK example, using an explicit protected EngineConfig.
//! No Agent profile, Node, Python or host connector is required. This creates
//! one PRIVATE workspace with a stable operation ID, then reads its metadata.
use peerwork_runtime::{
    communication_runtime::EngineConfig,
    participant::{Invoke, ParticipantClient, Scope},
};
use serde_json::json;
use std::{path::Path, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: participant_program PRIVATE_ENGINE_CONFIG.json")?;
    let config = EngineConfig::load(Path::new(&path))?.participant_config();
    let client = ParticipantClient::open(config).await?;
    let result=async{
        // A caller's wait budget never means "wait for another model". Once
        // admitted, the engine owns continuation even if this future is dropped.
        let operation=client.invoke(Invoke::new("example-create","structure.workspace.create",Scope::default(),json!({"name":"Program participant example"})),Duration::from_secs(5)).await?;
        if operation.state!="ACCEPTED"{println!("{}",serde_json::to_string(&operation)?);return Ok::<_,Box<dyn std::error::Error>>(());}
        let workspace=operation.outcome.as_ref().and_then(|value|value["result"]["structure"]["workspace_id"].as_str()).ok_or("verified workspace result missing")?;
        let metadata=client.request(Invoke::new("metadata","structure.workspace.get",Scope{workspace_id:Some(workspace.into()),..Default::default()},json!({}))).await?;
        println!("{}",json!({"operation_id":operation.operation_id,"command_id":operation.command_id,"metadata":metadata}));Ok(())
    }.await;
    client.close().await?;
    result
}
