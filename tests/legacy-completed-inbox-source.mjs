// Test-created historical Owner source with a completed or interrupted ACK.
// The old client signs all workspace, admission, and coordination operations.
import {generateKeyPairSync} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';

const [origin,sourceDir,legacyRoot,mode='complete']=process.argv.slice(2);
if(!origin||!sourceDir||!legacyRoot||!['complete','before-ack'].includes(mode))throw new Error('LEGACY_INBOX_INPUT_INVALID');
mkdirSync(sourceDir,{recursive:true,mode:0o700});
const modulePath=join(legacyRoot,'dist-workspace/src/workspace-secure-agent.js');
const {SecureAgentClient}=await import(pathToFileURL(modulePath).href);
const open=async(name)=>{
 const directory=join(sourceDir,name);mkdirSync(directory,{recursive:true,mode:0o700});
 const privateKey=generateKeyPairSync('ed25519').privateKey;
 const pemPath=join(directory,'owner.pem'),statePath=join(directory,'agent.state'),intentDbPath=join(directory,'workspace-intents.sqlite');
 writeFileSync(pemPath,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
 const agent=await SecureAgentClient.open({baseUrl:new URL(origin).origin,privateKey,statePath,intentDbPath});
 return {agent,pemPath,statePath,intentDbPath};
};
const owner=await open('owner'),member=await open('member');
try{
 const created=await owner.agent.create('Historical completed inbox receipt','PRIVATE',{structure:true,coordination:true});
 const workspaceId=created.workspaceId;
 await owner.agent.publishIdentity();await member.agent.publishIdentity();
 await owner.agent.trustIdentity(member.agent.identity.actorId);
 await member.agent.trustIdentity(owner.agent.identity.actorId);
 const journal=await owner.agent.journal(workspaceId);
 if(journal.policy.payload.v!==2||journal.policy.payload.visibility!=='PRIVATE'||!journal.policy.payload.structure?.coordination)throw new Error('LEGACY_COORDINATION_SOURCE_INVALID');
 const coordination=journal.policy.payload.structure.coordination;
 const offer=await owner.agent.inviteActor(workspaceId,member.agent.identity.actorId,[{
  instance_id:coordination.instance_id,
  actions:['coordination.send','coordination.reply','coordination.ack','coordination.disposition','coordination.cancel','coordination.remind'],
  protocol_roles:['COLLABORATOR'],capabilities:['COORDINATE'],
 }],'Historical inbox member');
 await member.agent.decideAdmission(offer.payload.invite_id,'ACCEPT');
 await owner.agent.deliverAdmission(offer.payload.invite_id);
 await member.agent.receiveAdmission(offer.payload.invite_id);
 const sent=await member.agent.sendCoordination(workspaceId,[owner.agent.identity.actorId],'Completed Owner inbox receipt');
 const item=sent.items.find(row=>row.recipient===owner.agent.identity.actorId);
 if(!item)throw new Error('LEGACY_INBOX_ITEM_MISSING');
 if(mode==='before-ack'){
  const original=owner.agent.save.bind(owner.agent);let stopped=false;
  owner.agent.save=()=>{
   original();
   if(!stopped&&owner.agent.state.inbox_receipts?.[item.id]){
    stopped=true;throw new Error('TEST_STOP_AFTER_INBOX_MARKER');
   }
  };
  try{await owner.agent.acknowledge(workspaceId,item.id);}catch(error){
   if(error?.message!=='TEST_STOP_AFTER_INBOX_MARKER')throw error;
  }
  if(!stopped)throw new Error('LEGACY_INBOX_STOP_NOT_REACHED');
 }else await owner.agent.acknowledge(workspaceId,item.id);
 const current=await owner.agent.journal(workspaceId);
 const observed=current.coordination?.find(row=>row.id===item.id);
 if(!observed||Boolean(observed.ack)!==(mode==='complete')||(observed.ack&&observed.ack.author!==owner.agent.identity.actorId))throw new Error('LEGACY_INBOX_ACK_MISMATCH');
 const marker=owner.agent.state.inbox_receipts?.[item.id];
 if(!marker||marker.workspace_id!==workspaceId||marker.source_hash!==item.source_hash)throw new Error('LEGACY_INBOX_MARKER_MISSING');
 if(Object.keys(owner.agent.state.pending).length!==0||Object.keys(owner.agent.state.coordination_intents??{}).length!==0)throw new Error('LEGACY_INBOX_PENDING_NOT_EMPTY');
 process.stdout.write(JSON.stringify({
  workspace_id:workspaceId,owner_actor_id:owner.agent.identity.actorId,owner_key_id:owner.agent.identity.keyId,
  policy_v:current.policy.payload.v,item_id:item.id,source:marker.source,source_hash:marker.source_hash,
  signed_ack:mode==='complete',sequence:current.checkpoint.sequence,
  state_path:owner.statePath,pem_path:owner.pemPath,intent_db_path:owner.intentDbPath,
 })+'\n');
}finally{owner.agent.close();member.agent.close();}
