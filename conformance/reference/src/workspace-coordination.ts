import {workflowDeadlineReadable} from './workspace-workflow.js';
/** Deterministic recipient state derived only after source signature/structure verification. */
import type {SecureCommit,SecurePolicy} from './workspace-secure-contract.js';
import type {StructureRecord} from './workspace-structure-contract.js';
import {emptyCoordinationState,type CoordinationItem,type CoordinationState,type CoordinationEvidence,type CoordinationReference,type CoordinationWork} from './workspace-coordination-contract.js';
export const coordinationItemId=(workspace:string,source:string,recipient:string)=>`${workspace}.${source}.${recipient}`;
const check=(ok:unknown,code:string)=>{if(!ok)throw new Error(code);};
const terminal=(s:CoordinationWork)=>s==='HANDLED'||s==='DECLINED';
export function coordinationOutstanding(item:CoordinationItem,now:number){return item.lifecycle==='ACTIVE'&&(!item.schedule||item.schedule.not_before<=now)&&!terminal(item.work)&&(item.work!=='DEFERRED'||item.defer_until!<=now);}
export function applyCoordinationCommit(state:CoordinationState,commit:SecureCommit,policy:SecurePolicy,commitHash:string):{state:CoordinationState;reminders:string[]}{
 const c=policy.payload.structure?.coordination,p=commit.payload,items=new Map([...state.items].map(([id,item])=>[id,structuredClone(item)])),records=new Map(state.records),reminders:string[]=[];
 const members=new Set(policy.payload.members.map(m=>m.actor_id));
 for(const item of items.values())if(item.lifecycle==='ACTIVE'&&(!members.has(item.recipient)||!members.has(item.sender)))item.lifecycle='ACCESS_REVOKED';
 for(const item of items.values())if(item.lifecycle==='ACTIVE'&&item.schedule){
  const source=records.get(item.source.record_id),schema=source&&policy.payload.structure?.protocols.find(protocol=>protocol.protocol_digest===source.protocol_digest)?.schemas[source.schema_ref];
  if(!c||!schema?.workflow||!workflowDeadlineReadable(schema.workflow,schema.fields))item.lifecycle='POLICY_DISABLED';
  else if(p.structure?.heads.some(head=>head.entity_id===item.schedule!.entity_id&&head.record_id!==item.source.record_id))item.lifecycle='SUPERSEDED';
 }
 if(!c&&p.structure?.mode==='DELTA')check(!p.structure.records.some(r=>r.schema_ref.startsWith('coordination.')),'COORDINATION_NOT_ENABLED');
 if(!c||p.structure?.mode!=='DELTA')return {state:{items,records},reminders};
 check(members.has(c.coordinator),'COORDINATION_COORDINATOR_NOT_MEMBER');
 const add=(r:StructureRecord,recipient:string,reason:CoordinationItem['reasons'][number],schedule?:CoordinationItem['schedule'])=>{
  check(members.has(recipient),'COORDINATION_RECIPIENT_NOT_MEMBER');if(recipient===r.actor_id&&!schedule)return;
  const id=coordinationItemId(p.workspace_id,r.record_id,recipient)+(schedule?'.deadline':''),old=items.get(id);if(old){if(!old.reasons.includes(reason))old.reasons.push(reason);return;}
  items.set(id,{id,workspace_id:p.workspace_id,sender:r.actor_id,recipient,source:{record_id:r.record_id,revision:r.revision},source_hash:commitHash,source_sequence:p.sequence,created:r.created,reasons:[reason],...(schedule?{schedule}:{}),lifecycle:'ACTIVE',ack:null,work:'PENDING',version:0,disposition:null,defer_until:null,result:null,cancel:null});
 };
 for(const r of p.structure.records){
  const f=r.fields;if(r.schema_ref.startsWith('coordination.')){
   check(r.instance_id===c.instance_id&&r.protocol_digest===c.protocol_digest,'COORDINATION_INSTANCE_MISMATCH');
   if(r.schema_ref==='coordination.request'){
    check(![...records.values()].some(old=>old.schema_ref==='coordination.request'&&old.actor_id===r.actor_id&&old.fields.request_id===f.request_id),'COORDINATION_REQUEST_CONFLICT');
    check(Array.isArray(f.recipients)&&f.recipients.length>0&&f.recipients.length<=16&&new Set(f.recipients).size===f.recipients.length&&f.recipients.some(v=>v!==r.actor_id),'COORDINATION_RECIPIENTS_INVALID');
    for(const recipient of f.recipients as string[])add(r,recipient,'MENTION');
    if(f.source_ref){const ref=f.source_ref as CoordinationReference,target=records.get(ref.record_id);check(target&&target.revision===ref.revision,'COORDINATION_SOURCE_NOT_FOUND');if(target&&members.has(target.actor_id))add(r,target.actor_id,'REPLY');}
   }else{
    const item=items.get(String(f.item_id)),ref=f.source_ref as CoordinationReference;
    check(item&&item.workspace_id===p.workspace_id&&item.source.record_id===ref?.record_id&&item.source.revision===ref?.revision&&item.source_hash===f.source_hash,'COORDINATION_SOURCE_MISMATCH');if(!item)throw new Error('COORDINATION_ITEM_NOT_FOUND');
    const evidence:CoordinationEvidence={record_id:r.record_id,commit_hash:commitHash,sequence:p.sequence,author:r.actor_id};
    if(r.schema_ref==='coordination.ack'){
     check(!item.schedule||p.issued_at>=item.schedule.not_before,'COORDINATION_DEADLINE_NOT_DUE');
     check(item.recipient===r.actor_id,'COORDINATION_RECIPIENT_REQUIRED');check(item.lifecycle==='ACTIVE','COORDINATION_ITEM_CLOSED');item.ack??=evidence;
    }else if(r.schema_ref==='coordination.disposition'){
     check(item.recipient===r.actor_id,'COORDINATION_RECIPIENT_REQUIRED');check(item.lifecycle==='ACTIVE','COORDINATION_ITEM_CLOSED');check(item.ack,'COORDINATION_ACK_REQUIRED');check(f.expected_version===item.version,'COORDINATION_VERSION_CONFLICT');check(!terminal(item.work),'COORDINATION_WORK_TERMINAL');
     const status=f.state as CoordinationWork;check(['IN_PROGRESS','WAITING_FOR_INPUT','DEFERRED','HANDLED','DECLINED'].includes(status),'COORDINATION_WORK_INVALID');check(status==='DEFERRED'?Number.isSafeInteger(f.defer_until)&&Number(f.defer_until)>p.issued_at&&Number(f.defer_until)<=p.issued_at+366*86_400_000:f.defer_until===null,'COORDINATION_DEFER_INVALID');
     if(c.v===2){const result=f.result_ref as CoordinationReference|null;check(result===null||result&&records.get(result.record_id)?.revision===result.revision,'COORDINATION_RESULT_NOT_FOUND');item.result=result;}
     item.version++;item.work=status;item.defer_until=f.defer_until as number|null;item.disposition=evidence;
    }else if(r.schema_ref==='coordination.cancel'){
     check(r.actor_id===item.sender||r.actor_id===policy.payload.owner_id,'COORDINATION_SENDER_REQUIRED');check(item.lifecycle==='ACTIVE'||item.lifecycle==='CANCELLED','COORDINATION_ITEM_CLOSED');item.lifecycle='CANCELLED';item.cancel??=evidence;
    }else if(r.schema_ref==='coordination.remind'){
     check(r.actor_id===item.sender||r.actor_id===policy.payload.owner_id,'COORDINATION_SENDER_REQUIRED');check(item.lifecycle==='ACTIVE'&&!item.ack,'COORDINATION_REMINDER_NOT_NEEDED');reminders.push(item.id);
    }else throw new Error('COORDINATION_EVENT_UNKNOWN');
   }
  }else if(r.schema_ref==='discussion.message'&&f.reply_to){const ref=f.reply_to as CoordinationReference,target=records.get(ref.record_id);if(target&&members.has(target.actor_id))add(r,target.actor_id,'REPLY');}
  else {
   const schema=policy.payload.structure!.protocols.find(protocol=>protocol.protocol_digest===r.protocol_digest)?.schemas[r.schema_ref];
   const field=schema?.workflow?.assignee_field??(r.schema_ref==='task.revision'?'assignee':undefined);
   const assignee=field&&schema?.fields[field]?.protection==='server_readable'&&schema.fields[field]?.type==='optional_actor'?f[field]:null;
   if(typeof assignee==='string'){add(r,assignee,'ASSIGNMENT');if(r.revision>1)add(r,assignee,'TASK_UPDATE');}
   const w=schema?.workflow;
   if(w&&workflowDeadlineReadable(w,schema!.fields)&&typeof assignee==='string'&&w.deadline!.reminder!.active_states.includes(String(f[w.status_field]))){
    const due=f[w.deadline!.field];if(due!==null){check(Number.isSafeInteger(due)&&Number(due)>=0,'COORDINATION_DEADLINE_INVALID');
     add(r,assignee,'DEADLINE',{kind:'DEADLINE',not_before:Math.max(r.created,Number(due)-w.deadline!.reminder!.lead_ms),due_at:Number(due),entity_id:r.entity_id,instance_id:r.instance_id});}
   }
  }
  records.set(r.record_id,r);
 }
 return {state:{items,records},reminders};
}
export function coordinationSnapshot(state:CoordinationState){return [...state.items.values()].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);}
export {emptyCoordinationState};

export class CoordinationError extends Error {constructor(code:string,readonly sequence:number){super(code);}}
/** Shared replay checks the complete signed routing history; operational attempts are not Agent claims. */
export function replayCoordination(commits:SecureCommit[],policies:Map<string,SecurePolicy>,hashes:Map<number,string>,initial?:CoordinationState):CoordinationState{
 if(initial&&commits.some(c=>c.payload.recovery))throw new Error('COORDINATION_RECOVERY_REQUIRES_FULL_REPLAY');
 let state=initial??emptyCoordinationState();const ranges:{from:number;through:number}[]=[];
 for(const commit of [...commits].reverse()){if(ranges.some(r=>commit.payload.sequence>=r.from&&commit.payload.sequence<=r.through))continue;if(commit.payload.recovery)ranges.push({from:commit.payload.recovery.base.sequence+1,through:commit.payload.recovery.through.sequence});}
 for(const commit of commits){const p=commit.payload,policy=policies.get(p.policy_hash);if(!policy)throw new CoordinationError('COORDINATION_POLICY_MISSING',p.sequence);
  try{
   const excluded=ranges.some(r=>p.sequence>=r.from&&p.sequence<=r.through);
   if(excluded&&p.structure){
    // Retain only typed source-routing evidence, clearly quarantined. Excluded ACKs
    // and dispositions never acknowledge or complete an otherwise valid source.
    const sources=p.structure.records.filter(r=>!r.schema_ref.startsWith('coordination.')||r.schema_ref==='coordination.request'),sourceOnly={...commit,payload:{...p,structure:{...p.structure,records:sources,heads:[]}}} as SecureCommit;
    state=applyCoordinationCommit(state,sourceOnly,policy,hashes.get(p.sequence)!).state;
    for(const item of state.items.values())if(item.source_sequence===p.sequence){item.lifecycle='SOURCE_EXCLUDED';item.ack=null;item.work='PENDING';item.disposition=null;item.cancel=null;}
   }else state=applyCoordinationCommit(state,commit,policy,hashes.get(p.sequence)!).state;
   // Snapshot adoption makes exact old references available without retroactive notifications.
   for(const r of p.structure?.records??[])state.records.set(r.record_id,r);
  }catch(error){throw new CoordinationError(error instanceof Error?error.message:'COORDINATION_REPLAY_FAILED',p.sequence);}
 }
 return state;
}
