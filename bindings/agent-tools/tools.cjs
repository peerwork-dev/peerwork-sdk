'use strict';
// SPDX-License-Identifier: Apache-2.0
const fs=require('node:fs'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto');
const {ToolStore,privateFile,fail}=require('./store.cjs');
const clone=v=>JSON.parse(JSON.stringify(v));
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const hash=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
const profilePin=p=>hash({binding:p.binding,identityPath:p.kernel.identityPath,journalPath:p.kernel.journalPath,authority:p.kernel.authority??null});
const ok=o=>{if(!['ACCEPTED','COMPLETED'].includes(o?.state))throw Object.assign(Error('TOOLS_READ_INCOMPLETE'),{code:o?.code??o?.result?.structure?.error?.code??'TOOLS_READ_INCOMPLETE',outcome:summary(o)});return o.result;};
const identifier=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(v);
function validateValues(tool,values){
 const schema=tool.input_schema??{},fields=schema.fields??{},errors=[];
 for(const key of schema.required??[])if(!Object.hasOwn(values,key))errors.push({field:key,code:'MISSING_FIELD'});
 for(const [key,value] of Object.entries(values)){
  const field=fields[key];if(!field){if(schema.additionalProperties===false)errors.push({field:key,code:'UNKNOWN_FIELD'});continue;}
  let valid=true;
  if(field.type==='string')valid=typeof value==='string'&&(field.maxBytes===undefined||Buffer.byteLength(value)<=field.maxBytes);
  if(field.type==='integer')valid=Number.isSafeInteger(value)&&(field.minimum===undefined||value>=field.minimum)&&(field.maximum===undefined||value<=field.maximum);
  if(field.type==='boolean')valid=typeof value==='boolean';
  if(field.type==='enum')valid=field.values?.some(v=>JSON.stringify(v)===JSON.stringify(value));
  if(field.type==='exact_ref'){try{reference(value);}catch{valid=false;}}
  if(!valid)errors.push({field:key,code:'INVALID_FIELD'});
 }
 if(errors.length)throw Object.assign(Error('TOOLS_INPUT_INVALID'),{code:'TOOLS_INPUT_INVALID',outcome:{state:'NOT_SUBMITTED',phase:'PREPARATION',effect_certainty:'NOT_SUBMITTED',fields:errors,recovery:'FIX_INPUT_NEW_OPERATION'}});
}
function reference(value){if(typeof value==='object'&&value&&Object.keys(value).sort().join(',')==='record_id,revision'&&identifier(value.record_id)&&Number.isSafeInteger(value.revision)&&value.revision>0)return clone(value);if(typeof value==='string'){const m=/^([A-Za-z0-9_-]{1,128})@([1-9][0-9]*)$/.exec(value);if(m&&Number.isSafeInteger(Number(m[2])))return {record_id:m[1],revision:Number(m[2])};}fail('TOOLS_EXACT_REFERENCE_REQUIRED');}
function summary(out){const r=out?.result??{},error=r.structure?.error??{};return {state:out?.state??'PENDING',command_id:out?.command_id??r.command_id??null,event_sequence:r.event_sequence??r.structure?.event_sequence??null,produced_record_ids:r.produced_record_ids??r.structure?.produced_record_ids??[],code:out?.code??error.code??null,phase:out?.phase??error.phase??null,effect_certainty:out?.effect_certainty??(['ACCEPTED','COMPLETED'].includes(out?.state)?'COMMITTED':out?.state==='REJECTED'?'NO_EFFECT':'UNKNOWN'),recovery:out?.recovery??error.recovery??null,model_response:'NOT_ATTESTED'};}
function loadProfile(file){
 if(!path.isAbsolute(file))fail('TOOLS_ABSOLUTE_PROFILE_REQUIRED');const p=JSON.parse(privateFile(file));
 if(p.format!=='peerwork.agent-tools.v1'||!p.kernel||!p.binding||!path.isAbsolute(p.state_directory)||!path.isAbsolute(p.kernel.identityPath)||!path.isAbsolute(p.kernel.journalPath)||p.kernel.origin?.replace(/\/$/,'')!==p.binding.expected_origin?.replace(/\/$/,''))fail('TOOLS_PROFILE_INVALID');
 if(p.connector_config&&!path.isAbsolute(p.connector_config))fail('TOOLS_PROFILE_INVALID');
 for(const [alias,c] of Object.entries(p.contacts??{})){if(!identifier(alias)||!identifier(c.actor_id)||!c.send||!identifier(c.send.tool))fail('TOOLS_CONTACT_INVALID');for(const mapping of [c.send,c.reply].filter(Boolean)){if(!identifier(mapping.tool)||!mapping.values||typeof mapping.values!=='object'||Array.isArray(mapping.values)||!Number.isSafeInteger(mapping.body_record_index??0)||(mapping.body_record_index??0)<0)fail('TOOLS_CONTACT_INVALID');if(mapping===c.reply&&!identifier(mapping.reference_field))fail('TOOLS_CONTACT_INVALID');}}
 return p;
}
function initProfile(file,receiverFile){
 if(!path.isAbsolute(file)||!path.isAbsolute(receiverFile))fail('TOOLS_ABSOLUTE_PROFILE_REQUIRED');const r=JSON.parse(privateFile(receiverFile));
 const p={format:'peerwork.agent-tools.v1',kernel:r.kernel,binding:r.binding,state_directory:path.join(r.state_directory,'agent-tools'),connector_config:receiverFile,contacts:{}};
 const directory=path.dirname(file);const s=fs.lstatSync(directory);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077))fail('TOOLS_STATE_NOT_PRIVATE');fs.writeFileSync(file,JSON.stringify(p,null,2)+'\n',{flag:'wx',mode:0o600});try{loadProfile(file);}catch(e){fs.unlinkSync(file);throw e;}return {state:'CONFIGURED',profile:file,actor_id:p.binding.expected_actor,workspace_id:p.binding.workspace_id,instance_id:p.binding.instance_id,next:'protocol'};
}
function outputRow(row){return {operation_id:row.id,...(row.outcome??{state:row.phase==='PREPARING'||row.phase==='PREPARED'?'NOT_SUBMITTED':'PENDING',phase:row.phase,effect_certainty:row.phase==='SUBMITTING'?'UNKNOWN':'NOT_SUBMITTED',recovery:'RESUME_SAME_INTENT',target:row.input?.target??null}),audience:'WORKSPACE_INSTANCE_SHARED',model_response:'NOT_ATTESTED',next:(row.outcome?.state==='PENDING'||!row.outcome?'recover ':'status ')+row.id};}
function localState(file,{operation_id,after='',limit=16}={}){
 const profile=loadProfile(file);if(!fs.existsSync(path.join(profile.state_directory,'agent-tools.sqlite')))fail('TOOLS_OPERATION_NOT_FOUND');const store=new ToolStore(profile.state_directory,profilePin(profile));
 try{return operation_id?{...outputRow(store.row(operation_id)),observation:'LOCAL_CACHED'}:store.page(after,limit);}finally{store.close();}
}
class AgentTools{
 constructor(sdk,kernel,profile){
  this.sdk=sdk;this.kernel=kernel;this.profile=clone(profile);this.session=sdk.protocolSession(kernel,profile.binding);
  this.store=new ToolStore(profile.state_directory,profilePin({...profile,binding:this.session.binding}));
 }
 static async open(file,sdk=require('@peerwork/agent-sdk')){const p=loadProfile(file),kernel=await sdk.openKernel(p.kernel);return new AgentTools(sdk,kernel,p);}
 async context(refresh=false){
  const cached=this.store.get('context');if(cached&&!refresh)return JSON.parse(cached);
  const described=await this.session.describe();ok(described.outcome);const current=ok(await this.session.state());const context={...described.context,revision:current.revision??current.structure?.revision,authorization:'ADVISORY_CACHED_TOOLS_BACKEND_ENFORCES_CURRENT_GRANTS'};
  if(!Number.isSafeInteger(context.revision)||context.revision<1)fail('TOOLS_CONTEXT_INVALID');this.store.set('context',JSON.stringify(context));return context;
 }
 async inspect(){return ok(await this.sdk.protocols(this.kernel).inspect({workspace_id:this.profile.binding.workspace_id,instance_id:this.profile.binding.instance_id})).structure;}
 contact(alias){const c=this.profile.contacts?.[alias];if(!c)fail('TOOLS_CONTACT_NOT_CONFIGURED');return clone(c);}
 input(kind,{to,tool,values={},text,reply_to,expected_revision}={}){
  if(!['send','reply','action'].includes(kind))fail('TOOLS_ACTION_INVALID');
  const target=kind==='action'?null:{alias:to,...this.contact(to)},mapping=kind==='action'?{tool,values,body_record_index:0}:target[kind];if(!mapping)fail('TOOLS_REPLY_NOT_CONFIGURED');
  if(text!==undefined&&(typeof text!=='string'||Buffer.byteLength(text)>16384||Buffer.from(text).toString('utf8')!==text))fail('TOOLS_BODY_INVALID');
  if(kind!=='action'&&(typeof text!=='string'||text.length===0))fail('TOOLS_BODY_REQUIRED');
  const selected=clone(mapping.values);if(kind==='reply'){if(Object.hasOwn(selected,mapping.reference_field))fail('TOOLS_REPLY_MAPPING_INVALID');selected[mapping.reference_field]=reference(reply_to);}
  if(expected_revision!==undefined&&(!Number.isSafeInteger(expected_revision)||expected_revision<1))fail('TOOLS_REVISION_INVALID');
  return {kind,target:target?{alias:to,actor_id:target.actor_id,...(target.route_id?{route_id:target.route_id}:{})}:null,tool:mapping.tool,values:selected,...(text===undefined?{}:{text,body_record_index:mapping.body_record_index??0}),...(expected_revision===undefined?{}:{expected_revision})};
 }
 async perform(kind,request,{operation_id=randomUUID(),onReserved=()=>{}}={}){
  if(!identifier(operation_id))fail('TOOLS_OPERATION_ID_INVALID');const input=this.input(kind,request);this.store.reserve(operation_id,hash(input),input);onReserved({operation_id,state:'RESERVED'});return this.recover(operation_id);
 }
 async recover(id){
  this.store.claim(id);try{
   let row=this.store.row(id);if(['ACCEPTED','COMPLETED','REJECTED'].includes(row.outcome?.state))return this.output(row);
   if(!row.prepared){
    const context=await this.context(),input=row.input,tool=context.tools.find(t=>t.name===input.tool);if(!tool)fail('TOOLS_ACTION_NOT_DECLARED');validateValues(tool,input.values);
    const refs=[];for(const [field,schema] of Object.entries(tool.input_schema?.fields??{}))if(schema.type==='exact_ref'&&input.values[field]!==undefined){const r=reference(input.values[field]);if(!refs.some(v=>v.record_id===r.record_id&&v.revision===r.revision))refs.push(r);}
    const prepared={action:'structure.action',workspace_id:this.profile.binding.workspace_id,instance_id:this.profile.binding.instance_id,protocol_digest:this.profile.binding.protocol_digest,expected_instance_revision:input.expected_revision??context.revision,idempotency_key:'agent-tools:'+hash([this.profile.binding,id]),exact_input_refs:refs,body:{action_id:tool.action,structure:input.values},...(input.text===undefined?{}:{plaintext_contents:[{record_index:input.body_record_index,text:input.text}]})};
    this.store.prepare(id,prepared);row=this.store.row(id);
   }
   this.store.submitting(id);
   // One native intent owns signatures, encryption, transport and reconciliation.
   // A transport exception leaves this exact prepared input saved for recovery.
   let outcome;
   try{outcome=row.outcome?.command_id?await this.kernel.resumeStructureIntent(row.outcome.command_id):await this.kernel.executeStructureIntent(row.prepared);}
   catch(error){const saved={state:'PENDING',command_id:row.outcome?.command_id??null,event_sequence:null,produced_record_ids:[],code:/^[A-Z][A-Z0-9_]{2,100}$/.test(error.code??'')?error.code:'TOOLS_SUBMISSION_UNCONFIRMED',phase:'SUBMISSION',effect_certainty:'UNKNOWN',recovery:'RESUME_SAME_INTENT',target:row.input?.target??row.outcome?.target??null,model_response:'NOT_ATTESTED'};this.store.finish(id,saved);return this.output(this.store.row(id));}
   const saved={...summary(outcome),target:row.input?.target??row.outcome?.target??null};this.store.finish(id,saved);
   if(['ACCEPTED','COMPLETED'].includes(outcome.state)&&Number.isSafeInteger(outcome.result?.revision)){const cached=this.store.get('context');if(cached){const c=JSON.parse(cached);c.revision=outcome.result.revision;this.store.set('context',JSON.stringify(c));}}
   return this.output(this.store.row(id));
  }finally{this.store.release(id);}
 }
 output(row){return outputRow(row);}
 async status(id,{delivery=true,refresh=true}={}){
  let row=this.store.row(id);
  let observation;
  if(refresh&&row.outcome?.command_id&&!['ACCEPTED','COMPLETED','REJECTED'].includes(row.outcome.state)){
   try{const current=await this.kernel.status(row.outcome.command_id);if(['ACCEPTED','COMPLETED','REJECTED'].includes(current.state)){this.store.finish(id,{...summary(current),target:row.outcome.target});row=this.store.row(id);}}
   catch(error){observation={status:'UNAVAILABLE',code:error.code??'TOOLS_STATUS_UNAVAILABLE'};}
  }
  const out=this.output(row);if(observation)out.observation=observation;
  if(delivery&&out.event_sequence&&out.target){
   try{
   const client=this.sdk.delivery(this.kernel,this.profile.binding);let route;
   if(out.target.route_id)route=ok(await client.get(out.target.route_id)).structure.route;
   else{const page=ok(await client.routes({limit:32})).structure;route=page.routes.find(r=>r.actor_id===out.target.actor_id&&!r.closed);if(!route){out.delivery={status:page.next_after?'ROUTE_NOT_IN_PAGE':'NO_ACTIVE_ROUTE',next_after:page.next_after??null};return out;}}
   if(route.actor_id!==out.target.actor_id)fail('TOOLS_TARGET_MISMATCH');
   if(out.event_sequence<=route.start_sequence){out.delivery={status:'OUTSIDE_SUBSCRIPTION',route_id:route.route_id};return out;}
   const receipt=ok(await client.receipt(route.route_id,out.event_sequence)).structure;
   out.delivery={status:receipt.status,route_id:route.route_id,route_state:route.state,execution_state:route.execution_state,model_response:'NOT_ATTESTED'};
   }catch(error){if(error.code==='TOOLS_TARGET_MISMATCH')throw error;out.delivery={status:'UNAVAILABLE',code:error.code??'TOOLS_DELIVERY_STATUS_UNAVAILABLE'};}
  }
  return out;
 }
 operations(after='',limit=16){return this.store.page(after,limit);}
 records(query={}){return this.session.records(query);}
 updates(query={}){return this.session.updates(query);}
 record(ref){return this.session.record(reference(ref));}
 close(){this.store.close();}
}
module.exports={AgentTools,initProfile,loadProfile,localState,reference,summary,hash};
