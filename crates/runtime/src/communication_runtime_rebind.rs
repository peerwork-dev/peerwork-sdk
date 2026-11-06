//! Authenticated runtime coordination around the engine-owned sealed job.
//! No process launch, original config pathname or endpoint credential import.
use super::*;
use crate::participant_rebind::{HostRebindRequest,resident::{Request,Selection,Snapshot,Source}};

impl Runtime {
    fn rebind_sources(&self,engine:&str,subscriptions:&[crate::participant_dispatch::HostSubscription])->Result<Vec<Source>>{
        let owner=self.owners.get(engine).ok_or_else(||local("HOST_REBIND_ENGINE_NOT_FOUND"))?;
        let(clients,generations)=self.client_snapshot()?;
        subscriptions.iter().map(|subscription|{
            let client=clients.get(&subscription.client).ok_or_else(||local("HOST_REBIND_SOURCE_CLIENT_CHANGED"))?;
            if client.state_binding()!=owner.state_binding() || generations.get(&subscription.client)!=Some(&subscription.client_generation) {
                return Err(local("HOST_REBIND_SOURCE_CLIENT_CHANGED"));
            }
            subscription.watch.authorize(client.capability())?;
            Ok(Source{subscription:subscription.clone(),client:client.clone()})
        }).collect()
    }
    pub(super) async fn start_resident_rebind(self:&Arc<Self>,request:HostRebindRequest,decision:Option<crate::participant_rebind::HostRebindRecoveryRequest>)->Result<Value>{
        let owner=self.owners.get(&request.engine).ok_or_else(||local("HOST_REBIND_ENGINE_NOT_FOUND"))?.clone();
        let current=if let Some(decision)=decision {
            owner.resident_rebind(Request::Recover{request:request.clone(),decision}).await?
        }else{owner.resident_rebind(Request::Lookup(request.clone())).await?};
        let snapshot=if let Some(current)=current {
            if serde_json::to_value(&current.request).ok()!=serde_json::to_value(&request).ok(){return Err(local("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));}
            current
        }else{
            owner.resident_rebind(Request::Preflight).await?;
            let mut config=self.config.clone();
            let subscriptions={let hosts=self.hosts.lock().await;config.hosts=hosts.configurations();hosts.preflight_rebind(&request)?};
            let sources=self.rebind_sources(&request.engine,&subscriptions)?;
            // An explicit Codex session pin is a requested target, not proof
            // of attachment. Verify it only after the original selected host
            // owner has drained; opening a second physical owner is forbidden.
            let destination=if request.adapter["kind"]=="codex"&&request.adapter["expected_session_id"].as_str().is_some_and(|s|!s.is_empty()) {
                crate::participant_inbox::HostBinding::new(json!({"host":"CODEX_APP_SERVER",
                    "conversation_id":request.adapter["thread_id"],"endpoint":request.adapter["endpoint"],
                    "session_id":request.adapter["expected_session_id"]}))?
            }else{
                let adapter=request.adapter.clone();let executor=tokio::runtime::Handle::current();
                tokio::task::spawn_blocking(move||{
                    let host=crate::communication_host::Host::open(adapter,executor).map_err(local)?;
                    crate::participant_inbox::HostBinding::new(host.destination.clone())
                }).await.map_err(|_|local("HOST_REBIND_TARGET_HOST_FAILED"))??
            };
            owner.resident_rebind(Request::Prepare(Selection{config,request:request.clone(),destination,sources})).await?
                .ok_or_else(||local("HOST_REBIND_STATE_INVALID"))?
        };
        if !snapshot.finished&&!snapshot.aborted {
            self.hosts.lock().await.reserve_rebind(&snapshot)?;
            self.spawn_resident_rebind(&snapshot.request.engine).await;
        }
        Ok(snapshot.result())
    }
    async fn spawn_resident_rebind(self:&Arc<Self>,engine:&str){
        let mut tasks=self.rebind_tasks.lock().await;
        if tasks.get(engine).is_some_and(|task|!task.is_finished()){return;}
        let runtime=self.clone();let selected=engine.to_owned();
        let task=tokio::spawn(async move{runtime.drive_resident_rebind(selected).await;});
        tasks.insert(engine.into(),task);
    }
    pub(super) async fn resume_resident_rebinds(self:&Arc<Self>)->Result<()>{
        for (engine,owner) in &self.owners {
            if let Some(snapshot)=owner.resident_rebind(Request::Status).await? {
                if let Err(problem)=self.hosts.lock().await.reserve_rebind(&snapshot) {
                    // Conflicting recovered maintenance stays scoped and waits
                    // for the existing reservation. It cannot authorize claim
                    // IO until drain_rebind acquires that same reservation.
                    let _=owner.resident_rebind(Request::Problem{operation:snapshot.request.operation_id.clone(),problem}).await;
                }
                self.spawn_resident_rebind(engine).await;
            }
        }Ok(())
    }
    async fn target_health(&self,snapshot:&Snapshot)->Result<()> {
        let borrowed=self.hosts.lock().await.rebind_adapter(snapshot)?;
        let adapter=snapshot.request.adapter.clone();let scopes=snapshot.access_scopes.clone();
        let wanted=snapshot.destination.clone();let executor=tokio::runtime::Handle::current();
        let deadline=std::time::Instant::now()+Duration::from_secs(10);
        tokio::task::spawn_blocking(move||{
            let check=|host:&mut crate::communication_host::Host|->std::result::Result<(),&'static str>{
                if crate::participant_inbox::HostBinding::new(host.destination.clone()).map_err(|_|"HOST_REBIND_TARGET_SESSION_CHANGED")?!=wanted{return Err("HOST_REBIND_TARGET_SESSION_CHANGED");}
                for scope in scopes {let health=host.health(&scope)?;
                    if health["ready"]!=true && !(host.mode=="TOOL_ONLY"&&health["can_attempt"]==true){return Err("HOST_REBIND_TARGET_HOST_NOT_READY");}
                }Ok(())
            };
            if let Some(host)=borrowed {
                crate::communication_host::operation::with_host(&host,deadline,check).map_err(local)
            }else{
                let budget=crate::communication_host::operation::Budget::new(Duration::from_secs(10));
                let _operation=budget.scope("REBIND");budget.clamp(deadline);
                check(&mut crate::communication_host::Host::open_progress(adapter,executor,budget).map_err(local)?).map_err(local)
            }
        }).await.map_err(|_|local("HOST_REBIND_TARGET_HOST_FAILED"))?
    }
    async fn drive_resident_rebind(self:Arc<Self>,engine:String){
        let Some(owner)=self.owners.get(&engine).cloned() else{return;};
        let mut authorized=false;
        loop {
            if self.cancel.is_cancelled(){return;}
            let snapshot=match owner.resident_rebind(Request::Status).await {
                Ok(Some(snapshot))=>snapshot,Ok(None)=>return,Err(_)=>return,
            };
            let operation=snapshot.request.operation_id.clone();
            let work=async{
                if !authorized {
                    if !self.hosts.lock().await.drain_rebind(&snapshot)? {return Ok(false);}
                    if !snapshot.aborting {
                        let stopped=self.hosts.lock().await.take_drained_dispatchers(&snapshot)?;
                        for job in stopped {let _=job.task.await;}
                        self.target_health(&snapshot).await?;
                    }
                    let sources=match self.rebind_sources(&engine,&snapshot.subscriptions){
                        Ok(sources)=>sources,
                        // The owner permits an empty source set only for exact
                        // frozen-claim reconciliation or verified abort. No new
                        // receive authority or host delivery is restored.
                        Err(_)=>Vec::new(),
                    };
                    owner.resident_rebind(Request::Authorize{operation:operation.clone(),sources}).await?;
                    authorized=true;
                }
                if snapshot.rollback_ready {
                    let(clients,generations)=self.client_snapshot()?;
                    self.hosts.lock().await.restore_rebind(&snapshot,&clients,&generations,&self.directory,self.cancel.clone())?;
                    owner.resident_rebind(Request::Published{operation:operation.clone()}).await?;
                    self.hosts.lock().await.finish_rebind(&snapshot);return Ok(true);
                }
                if snapshot.local_committed {
                    let(clients,generations)=self.client_snapshot()?;
                    self.hosts.lock().await.publish_rebind(&snapshot,&clients,&generations,&self.directory,self.cancel.clone()).await?;
                    owner.resident_rebind(Request::Published{operation:operation.clone()}).await?;
                    self.hosts.lock().await.finish_rebind(&snapshot);
                    return Ok(true);
                }
                Ok::<_,ParticipantError>(false)
            }.await;
            let mut delay=Duration::from_millis(100);
            match work {
                Ok(true)=>return,
                Ok(false)=>(),
                Err(problem)=>{delay=Duration::from_secs(2);let _=owner.resident_rebind(Request::Problem{operation,problem}).await;},
            }
            tokio::select!{_=self.cancel.cancelled()=>return,_=tokio::time::sleep(delay)=>{}}
        }
    }
}
