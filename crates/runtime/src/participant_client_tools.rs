//! Shared client requests for resident IPC and attached embedded MCP tools.
//! The caller supplies an already-owned client; this never opens an engine.
use crate::{
    communication_runtime::ClientRequest,
    participant::{ParticipantClient, ParticipantError, ProgramWatch, Result},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub(crate) type Watches = tokio::sync::Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<ProgramWatch>>>>;
fn local(code: &str) -> ParticipantError { ParticipantError::local(code, "LOCAL_IPC") }

pub(crate) async fn call(client: &ParticipantClient, watches: &Watches, request: ClientRequest) -> Result<Value> {
    match request {
        ClientRequest::NotificationRead{batch,options,after,cursor,limit,max_bytes,..}if batch.is_empty()=>crate::communication_notifications::manual_read(client,options.as_ref(),after,cursor.as_deref(),limit,max_bytes).await,
        ClientRequest::Delivery{mode,..}if matches!(mode.as_str(),"status"|"pause")=>Ok(json!({"state":"NO_AUTOMATIC_HOST","messages_deleted":false,"application_consumption_changed":false})),
        ClientRequest::Delivery{..}|ClientRequest::NotificationPoll{..}|ClientRequest::NotificationValidate{..}|ClientRequest::NotificationObserve{..}|ClientRequest::NotificationRead{..}=>Err(local("RESIDENT_RUNTIME_REQUIRED_FOR_AUTOMATIC_DELIVERY")),
        ClientRequest::HostStatus=>Err(local("RESIDENT_RUNTIME_REQUIRED_FOR_HOST_STATUS")),
                ClientRequest::DeliveryStatus{options,item}=>client.delivery_status(&options,item).await,
                ClientRequest::Unwatch{options}=>{client.unwatch(&options).await?;watches.lock().await.remove(&options.key());Ok(json!({"state":"LOCAL_STOPPED","lease_expires_within_ms":15000,"messages_deleted":false}))},
                ClientRequest::Watch{options}=>{
                    let mut watches=watches.lock().await;
                    if !watches.contains_key(&options.key()){
                        if watches.len()>=8{return Err(local("WATCH_SCOPE_LIMIT"));}
                        let watch=client.watch(options.clone()).await?;watches.insert(options.key(),Arc::new(tokio::sync::Mutex::new(watch)));
                    }else{
                        let watch=watches.get(&options.key()).unwrap().clone().try_lock_owned().map_err(|_|local("WATCH_WAIT_IN_PROGRESS"))?;
                        if watch.options()!=&options{return Err(local("WATCH_BINDING_MISMATCH"));}
                    }
                    drop(watches);
                    serde_json::to_value(client.inbox(&options,0,32).await?).map_err(|_|local("IPC_RESPONSE_INVALID"))
                },
                ClientRequest::WatchNext{options,wait_ms}=>{
                    if wait_ms==0||wait_ms>30_000{return Err(local("WAIT_BUDGET_INVALID"));}
                    let watch=watches.lock().await.get(&options.key()).cloned().ok_or_else(||local("WATCH_NOT_FOUND"))?;
                    let mut watch=watch.try_lock_owned().map_err(|_|local("WATCH_WAIT_IN_PROGRESS"))?;
                    if watch.options()!=&options{return Err(local("WATCH_BINDING_MISMATCH"));}
                    match tokio::time::timeout(Duration::from_millis(wait_ms),watch.next()).await{
                        Ok(value)=>serde_json::to_value(value?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                        Err(_)=>Ok(json!({"state":"WAIT_EXPIRED","scope":"LOCAL_OBSERVATION_ONLY","watch_continues":true})),
                    }
                },
                ClientRequest::WaitInbox{options,after,limit,wait_ms}=>{
                    if !(1..=32).contains(&limit)||after>9_007_199_254_740_991{return Err(local("INBOX_SELECTION_INVALID"));}
                    if wait_ms==0||wait_ms>30_000{return Err(local("WAIT_BUDGET_INVALID"));}
                    // Attach a notification handle to the same owned mailbox,
                    // not a second remote receiver. Snapshot after every wake
                    // so an initial state/heartbeat cannot satisfy an arrival.
                    let mut watch=client.watch(options).await?;
                    let observed=async{loop{
                        watch.changed().await?;
                        let page=watch.page(after,limit).await?;
                        if !page.items.is_empty(){return serde_json::to_value(page).map_err(|_|local("IPC_RESPONSE_INVALID"));}
                    }};
                    match tokio::time::timeout(Duration::from_millis(wait_ms),observed).await{
                        Ok(out)=>out,
                        Err(_)=>Ok(json!({"state":"WAIT_EXPIRED","scope":"LOCAL_OBSERVATION_ONLY","watch_continues":true})),
                    }
                },
                ClientRequest::Inbox{options,after,limit}=>serde_json::to_value(client.inbox(&options,after,limit).await?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                ClientRequest::Consume{options,items}=>{client.consume(&options,items).await?;Ok(json!({"state":"LOCAL_CONSUMPTION_RECORDED","remote_ack":"ASYNCHRONOUS","model_response":"NOT_ATTESTED"}))},
                ClientRequest::Invoke{request,resolved_request,protocol_route,wait_ms}=>{if wait_ms>30_000{return Err(local("WAIT_BUDGET_INVALID"));}serde_json::to_value(client.invoke_resolved(request,resolved_request,protocol_route,Duration::from_millis(wait_ms)).await?).map_err(|_|local("IPC_RESPONSE_INVALID"))},
                ClientRequest::Request{request}=>client.request(request).await,
                ClientRequest::ResolveExecution{request}=>serde_json::to_value(client.resolve_execution(request).await?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                ClientRequest::Operation{operation_id}=>serde_json::to_value(client.operation(&operation_id).await?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                ClientRequest::OperationResult{operation_id,selection}=>client.operation_result(&operation_id,selection).await,
                ClientRequest::Recover{operation_id}=>serde_json::to_value(client.recover(&operation_id).await?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                ClientRequest::Operations{after,limit}=>client.operations(&after,limit).await,
                ClientRequest::Bindings=>serde_json::to_value(client.watch_bindings().await?).map_err(|_|local("IPC_RESPONSE_INVALID")),

        ClientRequest::Capabilities => Ok(json!({"format":"peerwork.participant-capability.v1","actor_id":client.actor_id(),"origin":client.origin(),"capability":client.capability(),"admin":false,"maturity":"EXPERIMENTAL","features":["attached-client-tools-v1","protocol-operation-routing-v1","space-conversation-v1"],"sdk_version":env!("CARGO_PKG_VERSION")})),
        ClientRequest::Binding | ClientRequest::Derive { .. } | ClientRequest::RevokeDerived { .. } => Err(local("RESIDENT_RUNTIME_REQUIRED_FOR_ADMINISTRATION")),
    }
}
