// Genuine public producer: ordinary create/action/admission only. Native code
// subsequently enables coordination; this process never does that for it.
import {generateKeyPairSync} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
const [origin,directory,reference,visibility]=process.argv.slice(2);
if(!origin||!directory||!reference||!['PRIVATE','PUBLIC'].includes(visibility))throw Error('INPUT');
const {SecureAgentClient}=await import(pathToFileURL(join(reference,'dist-workspace/src/workspace-secure-agent.js')).href);
const open=async name=>{
 const root=join(directory,name);mkdirSync(root,{recursive:true,mode:0o700});
 const privateKey=generateKeyPairSync('ed25519').privateKey;
 const pemPath=join(root,'owner.pem'),statePath=join(root,'agent.state'),intentDbPath=join(root,'workspace-intents.sqlite');
 writeFileSync(pemPath,privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
 return {agent:await SecureAgentClient.open({baseUrl:new URL(origin).origin,privateKey,statePath,intentDbPath}),pemPath,statePath,intentDbPath};
};
const owner=await open('owner'),member=await open('member');
try {
 const created=await owner.agent.create('Dedicated native coordination proof',visibility,{structure:visibility==='PUBLIC'});
 let journal=await owner.agent.journal(created.workspaceId);
 if(journal.policy.payload.structure?.coordination)throw Error('PREEXISTING_COORDINATION');
 const wiki=journal.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='wiki');
 if(!wiki)throw Error('WIKI_MISSING');
 await owner.agent.action(created.workspaceId,wiki.id,'wiki.create',{title:'Prior coordination data',body:'Preserved original record and protection'});
 if(visibility==='PRIVATE') {
  await owner.agent.publishIdentity();await member.agent.publishIdentity();
  await owner.agent.trustIdentity(member.agent.identity.actorId);await member.agent.trustIdentity(owner.agent.identity.actorId);
  const offer=await owner.agent.inviteActor(created.workspaceId,member.agent.identity.actorId,[{instance_id:wiki.id,actions:['wiki.create'],protocol_roles:['EDITOR'],capabilities:['EDIT']}],'Existing member before coordination');
  await member.agent.decideAdmission(offer.payload.invite_id,'ACCEPT');await owner.agent.deliverAdmission(offer.payload.invite_id);await member.agent.receiveAdmission(offer.payload.invite_id);
 }
 journal=await owner.agent.journal(created.workspaceId);
 const record=journal.objects.find(o=>o.kind==='records'&&o.value.payload?.title==='Prior coordination data');
 if(!record||Object.keys(owner.agent.state.pending).length||Object.keys(owner.agent.state.protocol_install_intents??{}).length)throw Error('SOURCE_INVALID');
 writeFileSync(join(directory,'source-policy.json'),JSON.stringify(journal.policy),{mode:0o600,flag:'wx'});
 writeFileSync(join(directory,'source-record.json'),JSON.stringify(record),{mode:0o600,flag:'wx'});
 process.stdout.write(JSON.stringify({workspace_id:created.workspaceId,owner_actor_id:owner.agent.identity.actorId,owner_key_id:owner.agent.identity.keyId,
  member_actor_id:member.agent.identity.actorId,state_path:owner.statePath,pem_path:owner.pemPath,intent_db_path:owner.intentDbPath,
  sequence:journal.checkpoint.sequence,visibility,policy_v:journal.policy.payload.v,prior_record_id:record.id,wiki_instance_id:wiki.id})+'\n');
}finally{owner.agent.close();member.agent.close();}
