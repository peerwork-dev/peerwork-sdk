//! Protocol workbench: offline semantic execution and explicit verified export.
//! Simulation never opens a transport or a protected production identity.
use crate::{kernel_identity::KernelIdentity, secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile,SecureReadProfileConfig}, secure_verified_read::TransportReplayedJournal};
use peerwork_core::{canonical::Path, crypto::sha256_hex,
    protocol_simulation::{build_fixture_json,project_fixture_json,simulate_json},
    wire_json::{canonical_wire_value,parse_wire_json_bounded,WireValue as W}};
use serde::Deserialize;
use serde_json::{json,Value};
use tokio_util::sync::CancellationToken;

#[derive(Debug,thiserror::Error)]
pub(crate) enum WorkbenchError {
    #[error("invalid workbench request")] Input,
    #[error("workbench operation cancelled before execution")] Cancelled,
    #[error("saved plan is unavailable; provide the original plan with the same digest")] PlanRequired,
    #[error(transparent)] Operation(#[from] crate::agent_operations::OperationIndexError),
    #[error("workbench byte or step limit exceeded")] Limit,
    #[error("verified export failed: {0}")] Read(#[from] SecureReadAccessError),
    #[error("the planned dependency changed before the next submission")]
    Stale { operation_id:String, completed_steps:usize, results:Vec<Value>, expected:String, actual:String },
    #[error("accepted effects differ from the offline prediction; inspect the verified result before planning further")]
    OutcomeChanged { operation_id:String, completed_steps:usize, results:Vec<Value>, expected:String, actual:String },
    #[error("protected workbench state is unavailable")] State,
    #[error("plan actor does not match the selected identity")] Actor,
    #[error("fixture is synthetic; export current verified state before online apply")] Synthetic,
    #[error(transparent)] Simulation(#[from] peerwork_core::protocol_simulation::SimulationError),
    #[error(transparent)] Action(#[from] crate::secure_action_access::PublicActionError),
}
impl WorkbenchError {
    pub(crate) fn code(&self)->&'static str {match self {Self::Cancelled=>"CANCELLED",Self::PlanRequired=>"PLAN_CONTENT_REQUIRED",Self::Operation(e)=>e.code(),Self::Input=>"WORKBENCH_INPUT_INVALID",Self::Limit=>"WORKBENCH_LIMIT",
        Self::Read(e)=>e.code(),Self::Stale{..}=>"PLAN_STALE",Self::OutcomeChanged{..}=>"PLAN_OUTCOME_CHANGED",Self::State=>"WORKBENCH_STATE",
        Self::Actor=>"PLAN_ACTOR_MISMATCH",Self::Synthetic=>"SYNTHETIC_PLAN",Self::Simulation(e)=>e.code,Self::Action(e)=>e.code()}}
    pub(crate) fn envelope(&self)->Value {
        if let Self::Simulation(e)=self {let mut v=serde_json::to_value(e).unwrap();v["ok"]=json!(false);v["simulated"]=json!(true);v["authoritative"]=json!(false);v["message"]=json!(self.to_string());return v;}
        if let Self::Action(crate::secure_action_access::PublicActionError::Intent(crate::secure_intents::SecureIntentError::Rejected(detail)))=self {
            let mut out=detail.envelope();out["ok"]=json!(false);out["message"]=json!(self.to_string());return out;
        }
        if let Self::Stale{operation_id,completed_steps,results,expected,actual} | Self::OutcomeChanged{operation_id,completed_steps,results,expected,actual}=self {
            return json!({"ok":false,"schema":"peerwork.operation-error.v1","code":self.code(),"stage":"revalidate",
                "message":self.to_string(),"operation_id":operation_id,"completed_steps":completed_steps,"results":results,
                "effect_certainty":if *completed_steps==0{"not_sent"}else{"partially_accepted"},
                "retryability":"review_new_plan","dependency_diff":{"expected":expected,"actual":actual},
                "recovery_hints":[{"action":"inspect_accepted_results_then_export_remaining_plan","preserve_operation_id":true}]});
        }
        json!({"ok":false,"schema":"peerwork.operation-error.v1","code":self.code(),"stage":match self {Self::Action(_)=>"apply",_=>"inspect"},
            "message":self.to_string(),"effect_certainty":if matches!(self,Self::Action(_)|Self::State|Self::PlanRequired|Self::Operation(_)|Self::Limit|Self::Read(_)){"unknown"}else{"not_sent"},
            "retryability":if matches!(self,Self::Action(_)){"recover_same_operation"}else{"correct_input"}})
    }
}
type R<T>=Result<T,WorkbenchError>;
fn parse(s:&str)->R<W>{parse_wire_json_bounded(s.as_bytes(),64,4*1024*1024).map_err(|_|WorkbenchError::Input)}
fn wire(v:&W)->R<String>{canonical_wire_value(v,Path::SecureArtifact).map_err(|_|WorkbenchError::Input)}
fn obj(fields:Vec<(&str,W)>)->W{W::Object(fields.into_iter().map(|(k,v)|(k.encode_utf16().collect(),v)).collect())}
fn text(s:&str)->W{W::String(s.encode_utf16().collect())}
fn num(n:u64)->W{W::Number(n as f64)}
fn get<'a>(v:&'a W,k:&str)->R<&'a W>{v.get(k).ok_or(WorkbenchError::Input)}
fn string(v:&W)->R<String>{v.as_string().ok_or(WorkbenchError::Input)}
fn array(v:&W)->R<&[W]>{if let W::Array(a)=v {Ok(a)}else{Err(WorkbenchError::Input)}}
fn integer(v:&W)->R<u64>{v.as_number().filter(|n|n.is_finite()&&*n>=0.0&&n.fract()==0.0&&*n<=9007199254740991.0).map(|n|n as u64).ok_or(WorkbenchError::Input)}
#[cfg(test)]
fn value(v:Value)->W{parse_wire_json_bounded(v.to_string().as_bytes(),64,4*1024*1024).expect("internal bounded JSON")}
fn set(v:&mut W,k:&str,next:W){if let W::Object(fields)=v {if let Some((_,old))=fields.iter_mut().find(|(n,_)|n.iter().copied().eq(k.encode_utf16())){*old=next}else{fields.push((k.encode_utf16().collect(),next));}}}
fn digest(v:&W)->R<String>{Ok(sha256_hex(wire(v)?.as_bytes()))}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRequest {profile:SecureReadProfileConfig,instance_ids:Vec<String>,time_ms:u64,#[serde(default)] cached:bool}
fn export_from(source:&TransportReplayedJournal,actor:&str,instances:&[String],time:u64)->R<String>{
    let policy=source.signed_policy_by_hash(source.replay().policy_hash()).ok_or(WorkbenchError::State)?;
    let policy=parse(std::str::from_utf8(policy).map_err(|_|WorkbenchError::Input)?)?;
    let selected=source.replay().objects().iter().filter(|o|{
        let kind=o.get("kind").and_then(W::as_string).unwrap_or_default();
        if matches!(kind.as_str(),"protocols"|"protocol_status"|"record_relations") {return true}
        let id=if kind=="instances" {o.get("id")}else{o.get("value").and_then(|v|v.get("instance_id"))};
        id.and_then(W::as_string).is_some_and(|id|instances.contains(&id))
    }).cloned().collect();
    let input=obj(vec![("schema",text("peerwork.protocol-export.v1")),("workspace_id",text(source.replay().workspace_id())),
        ("policy",policy),("objects",W::Array(selected)),("instance_ids",W::Array(instances.iter().map(|s|text(s)).collect())),
        ("actor_id",text(actor)),("source_digest",text(&sha256_hex(source.checkpoint_canonical_json().as_bytes()))),
        ("time_ms",num(time)),("sequence",num(source.replay().sequence()))]);
    project_fixture_json(&wire(&input)?).map_err(WorkbenchError::from)
}
fn export(input:&str,cancel:&CancellationToken)->R<String>{
    let q:ExportRequest=serde_json::from_str(input).map_err(|_|WorkbenchError::Input)?;
    if q.instance_ids.is_empty()||q.instance_ids.len()>32||q.time_ms>9007199254740991{return Err(WorkbenchError::Input)}
    let identity=KernelIdentity::inspect_existing(&q.profile.identity_path).map_err(|_|WorkbenchError::Actor)?;
    let profile=SecureReadProfile::new(q.profile.clone());
    if q.cached {profile.with_pinned_replay(cancel,|s|export_from(s,identity.actor_id(),&q.instance_ids,q.time_ms))}
    else{profile.with_latest_replay(cancel,|s|export_from(s,identity.actor_id(),&q.instance_ids,q.time_ms))}
}

fn execute(operation:&str,input:&str,cancel:&CancellationToken)->R<String>{
    if cancel.is_cancelled(){return Err(WorkbenchError::Cancelled)}
    if input.len()>4*1024*1024{return Err(WorkbenchError::Limit)}
    match operation {
        "compatibility"=>compatibility(input),
        "fixture"=>build_fixture_json(input).map_err(WorkbenchError::from),
        "simulate"=>simulate_json(input).map_err(WorkbenchError::from),
        "export"=>export(input,cancel),
        "plan"=>plan(input),
        "apply"=>apply(input,cancel),
        _=>Err(WorkbenchError::Input),
    }
}
/// Shared envelope for Python, Node and CLI. Core wire JSON remains lossless.
pub fn workbench_json(operation:&str,input:&str,cancel:&CancellationToken)->String{
    match execute(operation,input,cancel) {Ok(v)=>format!("{{\"ok\":true,\"value\":{v}}}"),Err(e)=>e.envelope().to_string()}
}

fn shape(v:&W,required:&[&str],optional:&[&str])->R<()> {
    let W::Object(fields)=v else{return Err(WorkbenchError::Input)};
    if required.iter().any(|k|v.get(k).is_none())||fields.iter().any(|(k,_)|
        !required.iter().chain(optional).any(|n|k.iter().copied().eq(n.encode_utf16()))){return Err(WorkbenchError::Input)}
    Ok(())
}
/// Only stable semantic dependencies enter this digest. Transport sequence,
/// provenance labels and native record creation timestamps are not predicates.
fn dependency_digest(fixture:&W)->R<String>{
    let mut policy=get(fixture,"policy")?.clone();
    if let W::Object(fields)=get_mut(&mut policy,"payload")? {
        fields.retain(|(k,_)|!k.iter().copied().eq("issued_at".encode_utf16()));
    }
    let mut objects=array(get(fixture,"objects")?)?.to_vec();
    for object in &mut objects {
        if let W::Object(fields)=get_mut(object,"value")? {
            fields.retain(|(k,_)|!["created","updated"].iter().any(|n|k.iter().copied().eq(n.encode_utf16())));
        }
    }
    objects.sort_by_key(|o|format!("{}:{}:{}",o.get("kind").and_then(W::as_string).unwrap_or_default(),
        o.get("id").and_then(W::as_string).unwrap_or_default(),o.get("revision").and_then(W::as_number).unwrap_or(0.0)));
    digest(&obj(vec![("workspace_id",get(fixture,"workspace_id")?.clone()),("policy",policy),("objects",W::Array(objects))]))
}
fn get_mut<'a>(v:&'a mut W,k:&str)->R<&'a mut W>{
    if let W::Object(fields)=v {fields.iter_mut().find(|(n,_)|n.iter().copied().eq(k.encode_utf16())).map(|(_,v)|v).ok_or(WorkbenchError::Input)}else{Err(WorkbenchError::Input)}
}
fn plan(input:&str)->R<String>{
    let request=parse(input)?;
    let first=parse(&simulate_json(input)?)?;
    let fixture=get(&request,"fixture")?.clone();
    let actors=array(get(&fixture,"actors")?)?;
    let original=array(get(&request,"steps")?)?;
    let produced=array(get(&first,"steps")?)?;
    if original.len()!=produced.len()||original.is_empty(){return Err(WorkbenchError::Input)}
    let mut steps=Vec::new();
    for (step,output) in original.iter().zip(produced) {
        let mut normalized=get(output,"input")?.clone();
        let selected=if let Some(a)=step.get("actor_id") {actors.iter().find(|v|v.get("name")==Some(a)||v.get("actor_id")==Some(a)).ok_or(WorkbenchError::Actor)?}
            else{actors.first().ok_or(WorkbenchError::Actor)?};
        set(&mut normalized,"actor_id",get(selected,"actor_id")?.clone());
        set(&mut normalized,"time_ms",get(output,"time_ms")?.clone());
        steps.push(normalized);
    }
    // Pin every semantic intermediate frontier, not only the final output.
    let mut current=fixture.clone();let mut checkpoints=vec![text(&dependency_digest(&current)?)];
    for step in &steps {
        let next=parse(&simulate_json(&wire(&obj(vec![("schema",text("peerwork.protocol-simulation.v1")),
            ("fixture",current),("steps",W::Array(vec![step.clone()]))]))?)?)?;
        current=get(&next,"fixture")?.clone();checkpoints.push(text(&dependency_digest(&current)?));
    }
    let mut output=obj(vec![("schema",text("peerwork.protocol-plan.v1")),("engine_version",text(peerwork_core::version())),
        ("fixture",fixture),("steps",W::Array(steps)),("dependency_checkpoints",W::Array(checkpoints)),
        ("predicted_steps",get(&first,"steps")?.clone()),("simulated",W::Bool(true)),("authoritative",W::Bool(false))]);
    let hash=digest(&output)?;set(&mut output,"plan_digest",text(&hash));
    let out=wire(&output)?;if out.len()>4*1024*1024{return Err(WorkbenchError::Limit)}Ok(out)
}

#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanProgress {plan_digest:String,next_step:usize,results:Vec<Value>,
    #[serde(default)] plan_json:Option<String>, #[serde(default)] review_required:bool}
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanStore {version:u8,binding:String,operations:std::collections::BTreeMap<String,PlanProgress>}
fn plan_child(id:&str,plan:&str,step:usize)->String {
    peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(format!("peerwork.plan.v1\0{id}\0{plan}\0{step}").as_bytes()))
}
fn apply(input:&str,cancel:&CancellationToken)->R<String>{
    let q=parse(input)?;shape(&q,&["profile","operation_id"],&["plan"])?;
    let raw_config:SecureReadProfileConfig=serde_json::from_str(&wire(get(&q,"profile")?)?).map_err(|_|WorkbenchError::Input)?;
    let operation_id=string(get(&q,"operation_id")?)?;
    if !valid_operation_id(&operation_id){return Err(WorkbenchError::Input)}
    // Validate supplied plan before opening production identity/profile state.
    if let Some(plan)=q.get("plan") { checked_plan_digest(plan)?; if get(get(get(plan,"fixture")?,"provenance")?,"kind")?.as_string().as_deref()!=Some("verified-export"){return Err(WorkbenchError::Synthetic)} }
    let config=resolved_profile(raw_config)?;
    let identity=KernelIdentity::inspect_existing(&config.identity_path).map_err(|_|WorkbenchError::Actor)?;
    let actor=identity.actor_id();
    let plan=if let Some(plan)=q.get("plan"){plan.clone()}else{
        if crate::secure_state::missing_in_private_parent(&config.state_dir.join("plan-operations.state")){return Err(WorkbenchError::PlanRequired)}
        let (_store,saved)=open_plan_store(&config,&identity)?;
        let progress=saved.operations.get(&operation_id).ok_or(WorkbenchError::PlanRequired)?;
        checked_saved_plan(progress,&config,actor)?.ok_or(WorkbenchError::PlanRequired)?
    }; // The read lock is dropped before the existing apply path acquires it.

    shape(&plan,&["schema","engine_version","fixture","steps","dependency_checkpoints","predicted_steps","simulated","authoritative","plan_digest"],&[])?;
    if string(get(&plan,"schema")?)?!="peerwork.protocol-plan.v1"||string(get(&plan,"engine_version")?)?!=peerwork_core::version(){return Err(WorkbenchError::Input)}
    let claimed=string(get(&plan,"plan_digest")?)?;
    let mut unsigned=plan.clone();if let W::Object(fields)=&mut unsigned{fields.retain(|(k,_)|!k.iter().copied().eq("plan_digest".encode_utf16()));}
    if digest(&unsigned)?!=claimed{return Err(WorkbenchError::Input)}
    let fixture=get(&plan,"fixture")?;
    if get(get(fixture,"provenance")?,"kind")?.as_string().as_deref()!=Some("verified-export"){return Err(WorkbenchError::Synthetic)}
    if string(get(fixture,"workspace_id")?)?!=config.workspace_id{return Err(WorkbenchError::Input)}
    let steps=array(get(&plan,"steps")?)?;
    let checkpoints=array(get(&plan,"dependency_checkpoints")?)?;
    if steps.is_empty()||steps.len()>64||checkpoints.len()!=steps.len()+1{return Err(WorkbenchError::Limit)}
    let instances=array(get(fixture,"instances")?)?.iter().map(|i|string(get(i,"instance_id")?)).collect::<R<Vec<_>>>()?;
    let time=integer(get(fixture,"time_ms")?)?;
    for step in steps {if string(get(step,"actor_id")?)?!=actor{return Err(WorkbenchError::Actor)}}
    let action_path=config.state_dir.join("action-intents.state");
    if !crate::secure_state::missing_in_private_parent(&action_path){
        let journal=crate::secure_intents::SecureIntentJournal::open(&action_path,&config.origin,actor).map_err(|_|WorkbenchError::State)?;
        if journal.action_operation(&operation_id).map_err(|_|WorkbenchError::State)?.is_some(){return Err(WorkbenchError::Operation(crate::agent_operations::OperationIndexError::Conflict))}
    }
    crate::agent_operations::bind(&config,actor,&operation_id,"protocol.plan.apply",&json!({"kind":"protocol.plan.apply","plan_digest":claimed}))?;
    let (store,mut saved)=open_plan_store(&config,&identity)?;
    if !saved.operations.contains_key(&operation_id)&&saved.operations.len()>=4096{return Err(WorkbenchError::Limit)}
    let mut progress=saved.operations.get(&operation_id).cloned().unwrap_or(PlanProgress{plan_digest:claimed.clone(),next_step:0,results:vec![],plan_json:None,review_required:false});
    if progress.plan_digest!=claimed||progress.next_step>steps.len()||progress.results.len()!=progress.next_step{return Err(WorkbenchError::State)}
    if let Some(previous)=checked_saved_plan(&progress,&config,actor)? {if wire(&previous)?!=wire(&plan)?{return Err(WorkbenchError::State)}}
    progress.plan_json=Some(wire(&plan)?);
    let persist=|saved:&PlanStore|->R<()>{let bytes=zeroize::Zeroizing::new(serde_json::to_vec(saved).map_err(|_|WorkbenchError::State)?);
        if bytes.len()>4*1024*1024{return Err(WorkbenchError::Limit)}store.write_exact(&bytes).map_err(|_|WorkbenchError::State)};
    saved.operations.insert(operation_id.clone(),progress.clone());persist(&saved)?;
    let profile=SecureReadProfile::new(config.clone());
    let actions=crate::secure_action_access::SecurePrivateActionAccess::new(config.clone());
    let fresh=||->R<W>{profile.with_latest_replay(cancel,|source|parse(&export_from(source,actor,&instances,time)?))};
    // A persisted prefix must be authenticated before any later step can POST.
    // Reuse this replay's fixture for the first new step's dependency precheck.
    let mut resumed_fixture=if progress.next_step>0&&progress.next_step<steps.len(){
        let completed=plan_completed_inputs(steps,progress.next_step,&operation_id,&claimed)?;
        let (current,results)=profile.with_latest_replay(cancel,|source|->R<_>{
            let results=actions.verify_completed_plan_actions(source,&completed)?;
            Ok((parse(&export_from(source,actor,&instances,time)?)?,results))
        })?;
        progress.results=results.into_iter().map(|v|serde_json::to_value(v).map_err(|_|WorkbenchError::State)).collect::<R<Vec<_>>>()?;
        saved.operations.insert(operation_id.clone(),progress.clone());persist(&saved)?;
        Some(current)
    }else{None};
    while progress.next_step<steps.len() {
        let i=progress.next_step;let step=&steps[i];
        let child=plan_child(&operation_id,&claimed,i);
        let already_prepared={let journal=crate::secure_intents::SecureIntentJournal::open(&config.state_dir.join("action-intents.state"),&config.origin,actor).map_err(|_|WorkbenchError::State)?;
            journal.action_operation(&child).map_err(|_|WorkbenchError::State)?.is_some()};
        let mut expected_checkpoint=None;
        if !already_prepared {
            let current=match resumed_fixture.take(){Some(value)=>value,None=>fresh()?};
            expected_checkpoint=Some(string(get(get(&current,"provenance")?,"source_digest")?)?);
            let actual=dependency_digest(&current)?; let expected=string(&checkpoints[i])?;
            if actual!=expected{progress.review_required=true;saved.operations.insert(operation_id.clone(),progress.clone());persist(&saved)?;return Err(WorkbenchError::Stale{operation_id:operation_id.clone(),completed_steps:i,results:progress.results.clone(),expected,actual})}
            // Re-run the real evaluator immediately before authoring. Its proof
            // does not reserve the state; the author below pins the revision
            // and the service enforces the actual commit checkpoint.
            simulate_json(&wire(&obj(vec![("schema",text("peerwork.protocol-simulation.v1")),("fixture",current),
                ("steps",W::Array(vec![step.clone()]))]))?)?;
        }
        resumed_fixture=None;
        let input=plan_action_input(step)?;
        let raw=actions.submit_new_json_with_checkpoint(input,&child,Some(integer(get(step,"expected_instance_revision")?)?),expected_checkpoint.as_deref(),cancel)?;
        let result:Value=serde_json::from_str(&raw).map_err(|_|WorkbenchError::State)?;
        if result["status"]!="ACCEPTED" {
            return Ok(json!({"schema":"peerwork.protocol-plan-progress.v1","status":"PENDING","operation_id":operation_id,
                "plan_digest":claimed,"completed_steps":i,"step":i,"result":result,
                "continuation":{"operation":"workbench.apply","workspace_id":config.workspace_id,"operation_id":operation_id,"plan_digest":claimed}}).to_string());
        }
        // Preserve the authenticated acceptance before checking the predicted
        // frontier: a mismatch cannot turn an already submitted step into not_sent.
        progress.next_step+=1;progress.results.push(result);
        saved.operations.insert(operation_id.clone(),progress.clone());persist(&saved)?;
        let current=fresh()?; let actual=dependency_digest(&current)?;let expected=string(&checkpoints[i+1])?;
        if actual!=expected{progress.review_required=true;saved.operations.insert(operation_id.clone(),progress.clone());persist(&saved)?;return Err(WorkbenchError::OutcomeChanged{operation_id:operation_id.clone(),completed_steps:progress.next_step,results:progress.results.clone(),expected,actual})}
    }
    // Reuse one final authenticated replay for both the predicted frontier and
    // every completed child. The local cursor/result DTO is never authority.
    let completed=plan_completed_inputs(steps,progress.next_step,&operation_id,&claimed)?;
    let (actual,verified_results)=profile.with_latest_replay(cancel,|source|->R<_>{
        let results=actions.verify_completed_plan_actions(source,&completed)?;
        let current=parse(&export_from(source,actor,&instances,time)?)?;
        Ok((dependency_digest(&current)?,results))
    })?;
    progress.results=verified_results.into_iter().map(|v|serde_json::to_value(v).map_err(|_|WorkbenchError::State)).collect::<R<Vec<_>>>()?;
    saved.operations.insert(operation_id.clone(),progress.clone());persist(&saved)?;
    let expected=string(checkpoints.last().ok_or(WorkbenchError::State)?)?;
    if actual!=expected{progress.review_required=true;saved.operations.insert(operation_id.clone(),progress.clone());persist(&saved)?;return Err(WorkbenchError::OutcomeChanged{operation_id:operation_id.clone(),completed_steps:progress.next_step,results:progress.results.clone(),expected,actual})}
    if progress.review_required {progress.review_required=false;saved.operations.insert(operation_id.clone(),progress.clone());persist(&saved)?;}
    Ok(json!({"schema":"peerwork.protocol-plan-progress.v1","status":"VERIFIED","operation_id":operation_id,
        "plan_digest":claimed,"completed_steps":progress.next_step,"results":progress.results,
        "atomic":false,"verification":"signed_history"}).to_string())
}

fn plan_completed_inputs(steps:&[W],count:usize,operation_id:&str,claimed:&str)->R<Vec<(String,crate::secure_action_access::PublicActionInput,u64)>>{
    steps.iter().enumerate().take(count).map(|(i,step)|Ok((
        plan_child(operation_id,claimed,i),plan_action_input(step)?,integer(get(step,"expected_instance_revision")?)?
    ))).collect()
}

fn plan_action_input(step:&W)->R<crate::secure_action_access::PublicActionInput>{
    Ok(crate::secure_action_access::PublicActionInput{
        action_id:string(get(step,"action_id")?)?,instance_id:string(get(step,"instance_id")?)?,
        body_json:wire(get(step,"body")?)?,exact_input_refs_json:Some(wire(get(step,"exact_input_refs")?)?),
        allocations_json:Some(wire(get(step,"allocations")?)?),command_id:None,issued_at_ms:None,
    })
}

fn checked_plan_digest(plan:&W)->R<String>{
    shape(plan,&["schema","engine_version","fixture","steps","dependency_checkpoints","predicted_steps","simulated","authoritative","plan_digest"],&[])?;
    if string(get(plan,"schema")?)?!="peerwork.protocol-plan.v1"||string(get(plan,"engine_version")?)?!=peerwork_core::version(){return Err(WorkbenchError::Input)}
    let claimed=string(get(plan,"plan_digest")?)?;
    let mut unsigned=plan.clone();if let W::Object(fields)=&mut unsigned{fields.retain(|(k,_)|!k.iter().copied().eq("plan_digest".encode_utf16()));}
    if digest(&unsigned)?!=claimed{return Err(WorkbenchError::Input)}
    Ok(claimed)
}
fn valid_operation_id(id:&str)->bool{!id.is_empty()&&id.len()<=128&&id.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'.'|b'_'|b'-'))}
fn resolved_profile(mut config:SecureReadProfileConfig)->R<SecureReadProfileConfig>{
    let (saved,_)=SecureReadProfile::new(config.clone()).local_active_view_config()?;
    config.owner_actor_id=Some(saved.owner_actor_id);config.owner_key_id=Some(saved.owner_key_id);config.authority=Some(saved.authority);
    Ok(config)
}
fn open_plan_store(config:&SecureReadProfileConfig,identity:&KernelIdentity)->R<(crate::secure_state::SecureStateStore,PlanStore)>{
    let origin=reqwest::Url::parse(&config.origin).map_err(|_|WorkbenchError::Input)?;
    let binding=sha256_hex(json!({"origin":origin.as_str(),"actor":identity.actor_id(),"key":identity.key_id(),"workspace":config.workspace_id,
        "owner":config.owner_actor_id,"owner_key":config.owner_key_id,"authority":config.authority}).to_string().as_bytes());
    let store=crate::secure_state::SecureStateStore::open(&config.state_dir.join("plan-operations.state")).map_err(|_|WorkbenchError::State)?;
    let saved=match store.read_exact_secret().map_err(|_|WorkbenchError::State)? {
        None=>PlanStore{version:1,binding:binding.clone(),operations:std::collections::BTreeMap::new()},
        Some(w) if w.len()<=4*1024*1024=>serde_json::from_slice::<PlanStore>(&w).map_err(|_|WorkbenchError::State)?,
        _=>return Err(WorkbenchError::State),
    };
    if saved.version!=1||saved.binding!=binding||saved.operations.len()>4096||saved.operations.keys().any(|id|!valid_operation_id(id)){return Err(WorkbenchError::State)}
    Ok((store,saved))
}
fn checked_saved_plan(progress:&PlanProgress,config:&SecureReadProfileConfig,actor:&str)->R<Option<W>>{
    if progress.results.len()!=progress.next_step{return Err(WorkbenchError::State)}
    let Some(raw)=&progress.plan_json else{return Ok(None)};
    let plan=parse(raw)?;
    shape(&plan,&["schema","engine_version","fixture","steps","dependency_checkpoints","predicted_steps","simulated","authoritative","plan_digest"],&[])?;
    let mut unsigned=plan.clone();if let W::Object(fields)=&mut unsigned{fields.retain(|(k,_)|!k.iter().copied().eq("plan_digest".encode_utf16()));}
    if digest(&unsigned)?!=progress.plan_digest||string(get(&plan,"plan_digest")?)?!=progress.plan_digest
        ||string(get(&plan,"schema")?)?!="peerwork.protocol-plan.v1"
        ||string(get(get(&plan,"fixture")?,"workspace_id")?)?!=config.workspace_id {return Err(WorkbenchError::State)}
    let steps=array(get(&plan,"steps")?)?;
    if steps.is_empty()||steps.len()>64||progress.next_step>steps.len()
        ||steps.iter().any(|s|s.get("actor_id").and_then(W::as_string).as_deref()!=Some(actor)){return Err(WorkbenchError::State)}
    Ok(Some(plan))
}
fn progress_summary(config:&SecureReadProfileConfig,id:&str,progress:&PlanProgress,total:Option<usize>)->Value{
    json!({"kind":"protocol.plan.apply","status":"PLAN_LOCAL_PROGRESS","workspace_id":config.workspace_id,
        "operation_id":id,"plan_digest":progress.plan_digest,"completed_steps":progress.next_step,"total_steps":total,
        "plan_saved":progress.plan_json.is_some(),"review_required":progress.review_required,
        "verification":"pending","effect_certainty":"unknown","freshness":"LOCAL_ONLY",
        "continuation":{"operation":"workbench.apply","workspace_id":config.workspace_id,"operation_id":id},
        "recovery_hints":[{"action":"explicitly_resume_saved_plan","precondition":"online_revalidation_before_each_submission"}]})
}
pub(crate) fn pending_plans(config:&SecureReadProfileConfig)->R<Value>{
    if crate::secure_state::missing_in_private_parent(&config.state_dir.join("plan-operations.state")){return Ok(json!([]))}
    let config=resolved_profile(config.clone())?;
    let identity=KernelIdentity::inspect_existing(&config.identity_path).map_err(|_|WorkbenchError::Actor)?;
    let (_store,saved)=open_plan_store(&config,&identity)?;let mut rows=Vec::new();
    for (id,progress) in &saved.operations {
        let plan=checked_saved_plan(progress,&config,identity.actor_id())?;
        let total=plan.as_ref().map(|p|array(get(p,"steps")?).map(|s|s.len())).transpose()?;
        if total.is_none_or(|n|progress.next_step<n)||progress.review_required {rows.push(progress_summary(&config,id,progress,total));}
    }
    Ok(Value::Array(rows))
}
pub(crate) fn recover_plan(config:&SecureReadProfileConfig,id:&str,cancel:&CancellationToken)->R<Value>{
    if cancel.is_cancelled(){return Err(WorkbenchError::Cancelled)}
    if !valid_operation_id(id){return Err(WorkbenchError::Input)}
    if crate::secure_state::missing_in_private_parent(&config.state_dir.join("plan-operations.state")){return Err(WorkbenchError::PlanRequired)}
    let config=resolved_profile(config.clone())?;
    let identity=KernelIdentity::inspect_existing(&config.identity_path).map_err(|_|WorkbenchError::Actor)?;
    let (_store,saved)=open_plan_store(&config,&identity)?;
    let progress=saved.operations.get(id).ok_or(WorkbenchError::PlanRequired)?;
    let plan=checked_saved_plan(progress,&config,identity.actor_id())?;
    let total=plan.as_ref().map(|p|array(get(p,"steps")?).map(|s|s.len())).transpose()?;
    // Cursor/results are local state, not a newly authenticated acceptance proof.
    Ok(progress_summary(&config,id,progress,total))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request()->String {
        let manifest=json!({"name":"test.counter","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{},"initial_state":{"count":0},
            "actions":[{"id":"set","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},
            "variants":[{"when":[{"op":"eq","left":{"from":"state","path":["count"]},"right":{"from":"literal","value":0}}],
            "effects":[{"op":"set","path":["count"],"value":{"from":"literal","value":1}}]}]}]});
        let f=build_fixture_json(&json!({"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"v1","manifest":manifest}]}).to_string()).unwrap();
        format!("{{\"schema\":\"peerwork.protocol-simulation.v1\",\"fixture\":{f},\"steps\":[{{\"instance_id\":\"v1\",\"action_id\":\"set\"}}]}}")
    }
    #[test]
    fn offline_plan_freezes_concrete_inputs_and_intermediate_dependencies(){
        let q=request();let a=plan(&q).unwrap();assert_eq!(a,plan(&q).unwrap());
        let p=parse(&a).unwrap();let steps=array(get(&p,"steps").unwrap()).unwrap();
        assert!(steps[0].get("expected_instance_revision").is_some());
        assert!(steps[0].get("actor_id").is_some());
        let hashes=array(get(&p,"dependency_checkpoints").unwrap()).unwrap();
        assert_eq!(hashes.len(),2);assert_ne!(hashes[0],hashes[1]);
        let result=workbench_json("plan",&q,&CancellationToken::new());
        assert!(result.starts_with(r#"{"ok":true,"#));
        assert!(result.contains(r#""authoritative":false"#));
    }
    #[test]
    fn saved_plan_is_lossless_and_cannot_be_rebound_or_claim_fresh_acceptance(){
        let mut q=parse(&request()).unwrap();
        let steps=get_mut(&mut q,"steps").unwrap();
        if let W::Array(steps)=steps {set(&mut steps[0],"body",obj(vec![("source",W::String(vec![0xd800]))]));}
        let raw=plan(&wire(&q).unwrap()).unwrap();let p=parse(&raw).unwrap();
        let actor=string(get(&array(get(&p,"steps").unwrap()).unwrap()[0],"actor_id").unwrap()).unwrap();
        let workspace=string(get(get(&p,"fixture").unwrap(),"workspace_id").unwrap()).unwrap();
        let config:SecureReadProfileConfig=serde_json::from_value(json!({"origin":"https://example.invalid/","state_dir":"/unused","identity_path":"/unused/id","workspace_id":workspace})).unwrap();
        let mut progress=PlanProgress{plan_digest:checked_plan_digest(&p).unwrap(),next_step:0,results:vec![],plan_json:Some(raw.clone()),review_required:false};
        let stored=serde_json::to_vec(&progress).unwrap();let restored:PlanProgress=serde_json::from_slice(&stored).unwrap();
        assert_eq!(restored.plan_json.as_deref(),Some(raw.as_str()));
        assert!(checked_saved_plan(&restored,&config,&actor).unwrap().is_some());
        assert!(checked_saved_plan(&restored,&config,"another-actor").is_err());
        let summary=progress_summary(&config,"saved-plan",&progress,Some(1));
        assert_eq!(summary["status"],"PLAN_LOCAL_PROGRESS");assert_eq!(summary["effect_certainty"],"unknown");
        assert_eq!(summary["verification"],"pending");assert!(summary.get("plan_json").is_none());
        progress.plan_digest="0".repeat(64);assert!(checked_saved_plan(&progress,&config,&actor).is_err());
        progress.plan_json=None;assert!(checked_saved_plan(&progress,&config,&actor).unwrap().is_none());
    }
    #[test]
    fn cancellation_precedes_parsing_and_any_profile_access(){
        let cancel=CancellationToken::new();cancel.cancel();
        for op in ["fixture","simulate","plan","apply","export"] {
            let result:Value=serde_json::from_str(&workbench_json(op,"not JSON",&cancel)).unwrap();
            assert_eq!(result["code"],"CANCELLED");assert_eq!(result["effect_certainty"],"not_sent");
        }
    }
    #[test]
    fn diagnostics_never_erase_an_already_accepted_step() {
        let refusal=WorkbenchError::OutcomeChanged{operation_id:"saved-plan".into(),completed_steps:1,
            results:vec![json!({"status":"ACCEPTED","sequence":2})],expected:"a".into(),actual:"b".into()}.envelope();
        assert_eq!(refusal["code"],"PLAN_OUTCOME_CHANGED");
        assert_eq!(refusal["effect_certainty"],"partially_accepted");
        assert_eq!(refusal["results"][0]["status"],"ACCEPTED");
        let pre=WorkbenchError::Stale{operation_id:"saved-plan".into(),completed_steps:0,results:vec![],expected:"a".into(),actual:"b".into()}.envelope();
        assert_eq!(pre["effect_certainty"],"not_sent");
    }
    #[test]
    fn coverage_rejects_unknown_producers_instead_of_inventing_support() {
        assert!(supports_guarded_producers(&vec!["protocol.action".into(),"workspace.invitation.finalize".into()]));
        assert!(!supports_guarded_producers(&vec!["unqualified.maintenance".into()]));
        let report:Value=serde_json::from_str(&compatibility(r#"{"required_producers":["protocol.action","unqualified.maintenance"]}"#).unwrap()).unwrap();
        assert_eq!(report["supported"],false);
        assert_eq!(report["service_verified"],false);
        assert_eq!(report["producers"][1]["status"],"unknown");
    }
    #[test]
    fn applying_a_synthetic_plan_fails_before_opening_identity_or_creating_state(){
        let p=parse(&plan(&request()).unwrap()).unwrap();
        let q=obj(vec![("profile",value(json!({"origin":"https://example.invalid","state_dir":"/nonexistent/private","identity_path":"/nonexistent/key","workspace_id":"selected"}))),
            ("operation_id",text("apply-test")),("plan",p.clone())]);
        let mut q=q;let workspace=get(get(&p,"fixture").unwrap(),"workspace_id").unwrap().clone();
        set(get_mut(&mut q,"profile").unwrap(),"workspace_id",workspace);
        assert!(matches!(apply(&wire(&q).unwrap(),&CancellationToken::new()),Err(WorkbenchError::Synthetic)));
        let mut bad=p;set(&mut bad,"plan_digest",text(&"0".repeat(64)));set(&mut q,"plan",bad);
        assert!(matches!(apply(&wire(&q).unwrap(),&CancellationToken::new()),Err(WorkbenchError::Input)));
    }
}


pub(crate) fn with_profile_json(operation:&str,profile:&SecureReadProfileConfig,input:&str,cancel:&CancellationToken)->String {
    let result=(||->R<String>{
        let mut request=parse(input)?;
        if request.get("profile").is_some(){return Err(WorkbenchError::Input)}
        let config=serde_json::to_string(profile).map_err(|_|WorkbenchError::Input)?;
        set(&mut request,"profile",parse(&config)?);
        execute(operation,&wire(&request)?,cancel)
    })();
    match result{Ok(v)=>format!("{{\"ok\":true,\"value\":{v}}}"),Err(e)=>e.envelope().to_string()}
}


pub(crate) const DEFAULT_GUARDED_PRODUCERS:&[&str]=&[
    "protocol.action", "workspace.invitation.finalize", "protocol.install",
    "owner.guard_time.enable", "owner.guard_time.resume",
];
pub(crate) fn supports_guarded_producers(names:&[String])->bool {
    !names.is_empty() && names.len()<=32 && names.iter().all(|s|DEFAULT_GUARDED_PRODUCERS.contains(&s.as_str()))
}
fn compatibility(input:&str)->R<String> {
    #[derive(Deserialize)] #[serde(deny_unknown_fields)]
    struct Request {required_producers:Vec<String>}
    let q:Request=serde_json::from_str(input).map_err(|_|WorkbenchError::Input)?;
    if q.required_producers.is_empty()||q.required_producers.len()>32||q.required_producers.iter().any(|s|s.len()>128){return Err(WorkbenchError::Input)}
    Ok(json!({"schema":"peerwork.protocol-compatibility.v1","sdk_version":peerwork_core::version(),
        "scope":"local_producer_coverage","service_verified":false,
        "supported":supports_guarded_producers(&q.required_producers),
        "producers":q.required_producers.iter().map(|name|json!({"producer":name,
            "visibility":"PRIVATE","policy_mode":"ALL_COMMITS",
            "status":if DEFAULT_GUARDED_PRODUCERS.contains(&name.as_str()){"supported"}else{"unknown"},
            "service_feature":"signed-private-guard-time-v1",
            "evidence":"tests/unified-workbench-installed.mjs; tests/owner-guard-time-migration.mjs"})).collect::<Vec<_>>(),
        "requirements":["qualify all active writer SDK versions","declare every required maintenance and recovery producer","validate authenticated service capabilities before activation"],
        "protocol_versions":"Existing instances retain their exact manifest digest; publishing a new instance does not migrate them."}).to_string())
}
