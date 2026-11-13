'use strict';
// SPDX-License-Identifier: Apache-2.0
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const {ToolStore,privateFile,fail}=require('./store.cjs');
const clone=v=>JSON.parse(JSON.stringify(v));
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const hash=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
const profilePin=p=>hash({binding:p.binding,identityPath:p.kernel.identityPath,journalPath:p.kernel.journalPath,authority:p.kernel.authority??null});
const ok=o=>{if(!['ACCEPTED','COMPLETED'].includes(o?.state))throw Object.assign(Error('TOOLS_READ_INCOMPLETE'),{code:o?.code??o?.result?.structure?.error?.code??'TOOLS_READ_INCOMPLETE',outcome:summary(o)});return o.result;};
const identifier=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(v);
function reference(value){if(typeof value==='object'&&value&&Object.keys(value).sort().join(',')==='record_id,revision'&&identifier(value.record_id)&&Number.isSafeInteger(value.revision)&&value.revision>0)return clone(value);if(typeof value==='string'){const m=/^([A-Za-z0-9_-]{1,128})@([1-9][0-9]*)$/.exec(value);if(m&&Number.isSafeInteger(Number(m[2])))return {record_id:m[1],revision:Number(m[2])};}fail('TOOLS_EXACT_REFERENCE_REQUIRED');}
function summary(out){const r=out?.result??{},error=r.structure?.error??{};return {state:out?.state??'PENDING',command_id:out?.command_id??r.command_id??null,event_sequence:r.event_sequence??r.structure?.event_sequence??null,produced_record_ids:r.produced_record_ids??r.structure?.produced_record_ids??[],code:out?.code??error.code??null,phase:out?.phase??error.phase??null,effect_certainty:out?.effect_certainty??(['ACCEPTED','COMPLETED'].includes(out?.state)?'COMMITTED':out?.state==='REJECTED'?'NO_EFFECT':'UNKNOWN'),recovery:out?.recovery??error.recovery??null,model_response:'NOT_ATTESTED'};}
function loadProfile(file){
 if(!path.isAbsolute(file))fail('TOOLS_ABSOLUTE_PROFILE_REQUIRED');const p=JSON.parse(privateFile(file));
 if(p.format!=='peerwork.agent-tools.v1'||!p.kernel||!p.binding||!path.isAbsolute(p.state_directory)||!path.isAbsolute(p.kernel.identityPath)||!path.isAbsolute(p.kernel.journalPath)||p.kernel.origin?.replace(/\/$/,'')!==p.binding.expected_origin?.replace(/\/$/,''))fail('TOOLS_PROFILE_INVALID');
 if(p.connector_config&&!path.isAbsolute(p.connector_config))fail('TOOLS_PROFILE_INVALID');
 for(const [alias,c] of Object.entries(p.contacts??{})){if(!identifier(alias)||!identifier(c.actor_id)||!c.send||!identifier(c.send.tool))fail('TOOLS_CONTACT_INVALID');for(const mapping of [c.send,c.reply].filter(Boolean)){if(!identifier(mapping.tool)||!mapping.values||typeof mapping.values!=='object'||Array.isArray(mapping.values)||!Number.isSafeInteger(mapping.body_record_index??0)||(mapping.body_record_index??0)<0)fail('TOOLS_CONTACT_INVALID');if(mapping===c.reply&&!identifier(mapping.reference_field))fail('TOOLS_CONTACT_INVALID');}}
 return p;
}
function retired(){fail('TOOLS_EXECUTION_RETIRED_USE_NATIVE_PARTICIPANT');}
function initProfile(){retired();}
function outputRow(row){return {operation_id:row.id,...(row.outcome??{state:row.phase==='PREPARING'||row.phase==='PREPARED'?'NOT_SUBMITTED':'PENDING',phase:row.phase,effect_certainty:row.phase==='SUBMITTING'?'UNKNOWN':'NOT_SUBMITTED',recovery:'RESUME_SAME_INTENT',target:row.input?.target??null}),audience:'WORKSPACE_INSTANCE_SHARED',model_response:'NOT_ATTESTED',next:(row.outcome?.state==='PENDING'||!row.outcome?'recover ':'status ')+row.id};}
function localState(file,{operation_id,after='',limit=16}={}){
 const profile=loadProfile(file);if(!fs.existsSync(path.join(profile.state_directory,'agent-tools.sqlite')))fail('TOOLS_OPERATION_NOT_FOUND');const store=new ToolStore(profile.state_directory,profilePin(profile));
 try{return operation_id?{...outputRow(store.row(operation_id)),observation:'LOCAL_CACHED'}:store.page(after,limit);}finally{store.close();}
}
class AgentTools{
 constructor(sdk,kernel,profile){
  if(kernel.actor_id!==profile.binding.expected_actor||kernel.origin?.replace(/\/$/,'')!==profile.binding.expected_origin?.replace(/\/$/,''))fail('TOOLS_PROFILE_MISMATCH');
  this.kernel=kernel;this.profile=clone(profile);
  if(!fs.existsSync(path.join(profile.state_directory,'agent-tools.sqlite')))fail('TOOLS_OPERATION_NOT_FOUND');
  this.store=new ToolStore(profile.state_directory,profilePin(profile));
 }
 static async open(file,sdk){
  const p=loadProfile(file);if(!fs.existsSync(path.join(p.state_directory,'agent-tools.sqlite')))fail('TOOLS_OPERATION_NOT_FOUND');
  sdk??=require('@peerwork/agent-sdk');return new AgentTools(sdk,await sdk.openKernel(p.kernel),p);
 }
 async perform(){retired();}
 async recover(id){
  this.store.claim(id);try{
   let row=this.store.row(id);if(['ACCEPTED','COMPLETED','REJECTED'].includes(row.outcome?.state))return this.output(row);
   // Only a previously frozen operation can be reconciled. A historical
   // reservation without prepared input never reached native submission.
   if(!row.prepared&&!row.outcome?.command_id)return {...this.output(row),state:'NOT_SUBMITTED',effect_certainty:'NOT_SUBMITTED',code:'TOOLS_ORIGINAL_OPERATION_NOT_PREPARED'};
   this.store.submitting(id);
   // One native intent owns signatures, encryption, transport and reconciliation.
   // A transport exception leaves this exact prepared input saved for recovery.
   let outcome;
   try{outcome=row.outcome?.command_id?await this.kernel.resumeStructureIntent(row.outcome.command_id):await this.kernel.executeStructureIntent(row.prepared);}
   catch(error){const saved={state:'PENDING',command_id:row.outcome?.command_id??null,event_sequence:null,produced_record_ids:[],code:/^[A-Z][A-Z0-9_]{2,100}$/.test(error.code??'')?error.code:'TOOLS_SUBMISSION_UNCONFIRMED',phase:'SUBMISSION',effect_certainty:'UNKNOWN',recovery:'RESUME_SAME_INTENT',target:row.input?.target??row.outcome?.target??null,model_response:'NOT_ATTESTED'};this.store.finish(id,saved);return this.output(this.store.row(id));}
   const saved={...summary(outcome),target:row.input?.target??row.outcome?.target??null};this.store.finish(id,saved);
   return this.output(this.store.row(id));
  }finally{this.store.release(id);}
 }
 output(row){return outputRow(row);}
 async status(id,{refresh=true}={}){
  let row=this.store.row(id);
  let observation;
  if(refresh&&row.outcome?.command_id&&!['ACCEPTED','COMPLETED','REJECTED'].includes(row.outcome.state)){
   try{const current=await this.kernel.status(row.outcome.command_id);if(['ACCEPTED','COMPLETED','REJECTED'].includes(current.state)){this.store.finish(id,{...summary(current),target:row.outcome.target});row=this.store.row(id);}}
   catch(error){observation={status:'UNAVAILABLE',code:error.code??'TOOLS_STATUS_UNAVAILABLE'};}
  }
  const out=this.output(row);if(observation)out.observation=observation;
  return out;
 }
 operations(after='',limit=16){return this.store.page(after,limit);}
 close(){this.store.close();}
}
module.exports={AgentTools,initProfile,loadProfile,localState,reference,summary,hash};
