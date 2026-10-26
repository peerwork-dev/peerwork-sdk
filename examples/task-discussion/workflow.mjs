// SDK 0.2.3 recipe: all signing, encryption, verification and recovery are native.
import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
export const manifests=Object.fromEntries(['tasks','discussion'].map(name=>[name,JSON.parse(readFileSync(new URL(name+'.json',import.meta.url),'utf8'))]));
export const permissions={tasks:{actions:['task.create','task.update','task.report'],protocol_roles:['CONTRIBUTOR'],capabilities:['CREATE','UPDATE','REPORT']},discussion:{actions:['discussion.post','discussion.reply'],protocol_roles:['CONTRIBUTOR'],capabilities:['POST']}};
export function accepted(value){
 if(value.state==='PENDING'){const e=Error('Operation pending; resume its original command_id');Object.assign(e,{code:value.code,command_id:value.command_id,pending:true});throw e;}
 if(!['ACCEPTED','COMPLETED'].includes(value.state)){const error=value.result?.structure?.error??{};const e=Error(error.code??'OPERATION_REFUSED');Object.assign(e,{code:error.code,details:error.details,command_id:value.result?.command_id,effect_certainty:'NOT_APPLIED'});throw e;}
 return value.result;
}
/** Read-only payload/declaration diagnostics; mutation still rechecks authority and CAS. */
export async function preflightGrant(client,scope,body){
 const result=accepted(await client.executeStructureIntent({action:'structure.grant.get',...scope,body:{actor_id:body.actor_id,candidate:body}}));
 if(!result.structure.validation)throw Error('STRUCTURED_GRANT_DIAGNOSTICS_NOT_SUPPORTED');
 return result.structure.validation;
}
export async function installWorkflows(client,config,statePath){
 const selection={workspace_id:config.workspace_id,owner:client.actor_id,workers:config.workers,idempotency_prefix:config.idempotency_prefix,manifests};
 const digest=createHash('sha256').update(JSON.stringify(selection)).digest('hex');const state=existsSync(statePath)?JSON.parse(readFileSync(statePath,'utf8')):{schema:'peerwork.task-discussion-binding.v1',selection_digest:digest,workspace_id:config.workspace_id,intents:{},instances:{},grants:{}};
 if(state.selection_digest!==digest)throw Error('SETUP_SELECTION_CHANGED_USE_NEW_STATE');
 const save=()=>writeFileSync(statePath,JSON.stringify(state,null,2)+'\n',{mode:0o600});
 const execute=async(key,build)=>{if(!state.intents[key]){state.intents[key]=await build();save();}return accepted(await client.executeStructureIntent(state.intents[key])).structure;};
 for(const name of ['tasks','discussion']){
  if(!state.instances[name]){const m=manifests[name];const result=await execute('adopt-'+name,async()=>({action:'structure.adopt',workspace_id:config.workspace_id,idempotency_key:config.idempotency_prefix+'-adopt-'+name,body:{manifest:m,bootstrap_grant:{actions:m.actions.map(a=>a.id),protocol_roles:m.protocol_roles,capabilities:m.capabilities}}}));state.instances[name]={instance_id:result.instance_id,protocol_digest:result.protocol_digest,revision:result.revision??1};save();}
  for(const worker of config.workers){const key=name+'-'+worker.actor_id;if(state.grants[key])continue;const scope={workspace_id:config.workspace_id,...state.instances[name]};delete scope.revision;
   const result=await execute(key,async()=>{const prior=accepted(await client.executeStructureIntent({action:'structure.grant.get',...scope,body:{actor_id:worker.actor_id}})).structure.grant;return {action:'structure.grant.set',...scope,idempotency_key:config.idempotency_prefix+'-grant-'+key,body:{actor_id:worker.actor_id,membership_id:worker.membership_id,expected_grant_revision:prior?.grant_revision??null,...permissions[name]}};});state.grants[key]={actor_id:worker.actor_id,membership_id:worker.membership_id,grant_revision:result.grant_revision,...permissions[name]};save();
  }
 }
 return state;
}
export const ref=(record_id,revision)=>({record_id,revision});
export async function write(client,binding,which,action_id,structure,key,{refs=[],text}={}){
 const scope=binding.instances[which];return client.executeStructureIntent({action:'structure.action',workspace_id:binding.workspace_id,instance_id:scope.instance_id,protocol_digest:scope.protocol_digest,expected_instance_revision:scope.revision,idempotency_key:key,exact_input_refs:refs,body:{action_id,structure},...(text===undefined?{}:{plaintext_contents:[{record_index:0,text}]})});
}
export async function updateTicket(client,binding,task_ref,status,key,text){
 if(text===undefined){const scope=binding.instances.tasks;const prior=accepted(await client.executeStructureIntent({action:'structure.record.get',workspace_id:binding.workspace_id,instance_id:scope.instance_id,protocol_digest:scope.protocol_digest,body:task_ref}));const body=prior.opened_contents?.find(b=>b.record_id===task_ref.record_id);if(body?.state==='OPENED')text=body.text;else if(body?.state!=='NO_CONTENT')throw Error('TASK_BODY_NOT_AVAILABLE_NO_UPDATE_SUBMITTED');}
 return write(client,binding,'tasks','task.update',{task_ref,status},key,{refs:[task_ref],text});
}
