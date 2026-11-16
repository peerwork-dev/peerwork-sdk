//! Exact native entry point qualification against a disposable synthetic Space.
use super::*;

struct NativeRuntimeCleanup { executable:PathBuf, admin:PathBuf }
impl Drop for NativeRuntimeCleanup {
    fn drop(&mut self) {
        let _=std::process::Command::new(&self.executable).args(["runtime","admin"])
            .arg(&self.admin).arg("stop").output();
    }
}

#[cfg(unix)]
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires local TEST PostgreSQL, HTTP service and freshly built native CLI"]
async fn native_new_peer_approval_and_plain_repeat_preserve_original_installation() {
    use crate::{communication_runtime as ipc,participant::{ParticipantClient,Scope},
        participant::http_tests::{Service,configuration,mutate,install_synthetic_key}};
    use std::time::Duration;
    let service=Service::start();
    let root=crate::test_support::protected_test_dir();
    let owner_dir=root.path().join("owner");
    crate::secure_state::create_private_state_directory(&owner_dir).unwrap();
    let options=configuration(&owner_dir,&service.origin);
    let client=ParticipantClient::open(options.clone()).await.unwrap();
    let workspace=mutate(&client,"new-space","structure.workspace.create",&Scope::default(),json!({"name":"Native new Peer qualification"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(workspace.clone()),..Default::default()};
    let key=install_synthetic_key(&options,&workspace,&[93;32],None);
    mutate(&client,"new-key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    client.close().await.unwrap();
    let config=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("owner-runtime"),
        engines:vec![ipc::EngineConfig{name:"owner".into(),origin:options.origin.clone(),expected_actor:options.expected_actor.clone(),
            identity_path:options.identity_path.clone(),state_directory:options.state_directory.clone(),journal_path:Some(options.journal_path.clone()),
            authority:options.authority.clone(),allow_loopback_http:true,transport:options.transport.clone(),
            max_inflight:4,max_pending:16,max_stored_bytes:8*1024*1024,migration_sources:vec![]}],
        clients:vec![ipc::ClientConfig{name:"owner".into(),engine:"owner".into(),capability:Capability::owner()}],hosts:vec![]};
    let cancel=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
    let running=tokio::spawn(ipc::serve(config,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let mut owner=Connect::open(&root.path().join("owner-local")).unwrap();
    owner.register("owner",Registration{origin:service.origin.clone(),actor_id:options.expected_actor.clone(),endpoint_path:ready.client_endpoints["owner"].clone()}).await.unwrap();
    let executable=PathBuf::from(std::env::var("PEERWORK_PARTICIPANT_CLI").unwrap());
    let local=root.path().join("new-local");let project=root.path().join("project");
    std::fs::create_dir(&project).unwrap();
    async fn run(executable:&Path,args:&[String])->Value {
        let output=tokio::time::timeout(Duration::from_secs(45),tokio::process::Command::new(executable).args(args).kill_on_drop(true).output()).await.unwrap().unwrap();
        let value:Value=serde_json::from_slice(&output.stdout).unwrap_or_else(|_|panic!("{}",String::from_utf8_lossy(&output.stderr)));
        assert_eq!(output.status.code(),Some(if value["state"]=="PENDING"{2}else if value["state"]=="FAILED"{1}else{0}),"{value}");value
    }
    let mut first_args=vec!["connect".into(),"--local".into(),local.display().to_string(),"--project".into(),project.display().to_string(),
        "--new".into(),"--workspace".into(),workspace.clone(),"--origin".into(),service.origin.clone(),"--allow-loopback-http".into(),"--program".into()];
    // This test owns the explicit fresh local directory and default "peer"
    // handle. Install cleanup before launching its exact managed runtime so a
    // failed assertion or malformed CLI result cannot leave the child running.
    let cleanup=NativeRuntimeCleanup{executable:executable.clone(),admin:local.join("runtime-peer/admin.json")};
    let pending=run(&executable,&first_args).await;
    assert_eq!(pending["blocker"]["code"],"ADMISSION_APPROVAL_REQUIRED","{pending}");
    let authorization=AuthorizationRequest::from_input(pending["details"]["authorization_code"].clone()).unwrap();
    let (original_request,original_actor,identity,original_engine)={
        let selected=Connect::inspect(&local).unwrap();
        let (request,resume)=selected.resolve_input(serde_json::from_value(json!({})).unwrap()).unwrap();
        assert!(resume);assert!(request.send&&request.receive&&request.require_body_keys&&request.request_membership);
        let setup=&selected.registry.setups[&request.setup_id];
        assert!(!setup.agent_host_required);
        assert!(!request.needs_host(setup.agent_host_required));
        let engine=bootstrap::owned_runtime(&selected,"peer").unwrap().config.engines[0].clone();
        (request,selected.registry.participants["peer"].actor_id.clone(),std::fs::read(&engine.identity_path).unwrap(),engine)
    };
    let approved=tokio::time::timeout(Duration::from_secs(20),async{loop {
        let value=owner.approve("owner","native-new-approval",authorization.clone()).await.unwrap();
        if value["state"]!="PENDING"{break value;}tokio::time::sleep(Duration::from_millis(25)).await;
    }}).await.unwrap();
    assert_eq!(approved["state"],"APPROVED","{approved}");
    // Ordinary repeat has no --new, --join, --body-keys, --program, setup ID,
    // engine path or saved flags to reconstruct. It selects the original intent.
    first_args.truncate(5);
    let completed=run(&executable,&first_args).await;
    assert_eq!(completed["state"],"LOCAL_CONFIGURED","{completed}");
    assert_eq!(completed["owner_exchange_required"],false);
    assert_eq!(run(&executable,&first_args).await["state"],"LOCAL_CONFIGURED");
    let selected=Connect::inspect(&local).unwrap();
    let (same,resume)=selected.resolve_input(serde_json::from_value(json!({})).unwrap()).unwrap();
    assert!(resume);assert!(same==original_request);assert_eq!(selected.registry.setups.len(),1);
    assert!(!selected.registry.setups[&same.setup_id].agent_host_required);
    assert_eq!(selected.registry.participants["peer"].actor_id,original_actor);
    let owned=bootstrap::owned_runtime(&selected,"peer").unwrap();let engine=&owned.config.engines[0];
    assert_eq!(engine.identity_path,original_engine.identity_path);assert_eq!(engine.state_directory,original_engine.state_directory);assert_eq!(engine.journal_path,original_engine.journal_path);
    assert_eq!(std::fs::read(&engine.identity_path).unwrap(),identity);
    assert!(!std::fs::read_dir(&local).unwrap().any(|entry|entry.unwrap().file_name().to_string_lossy().starts_with("profile-")));
    assert_eq!(service.counts().await["actions"]["structure.member.set"],1);
    owned.stop().await.unwrap();drop(cleanup);cancel.cancel();running.await.unwrap().unwrap();
}
