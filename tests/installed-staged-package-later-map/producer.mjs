// Unmodified genuine staged-package producer, followed by a public legal action.
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {createHash,createPrivateKey} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const [origin,directory,reference,mode]=process.argv.slice(2),sdk=process.env.PEERWORK_TEST_SDK_ROOT;
if(mode!=='direct-staged-package-completed-end')throw Error('INPUT');
const helper=sdk+'/tests/legacy-owner-install-intent.mjs';
if(createHash('sha256').update(readFileSync(helper)).digest('hex')!=='2aad60bcb968470a433b2643f323eae582d55eac7c68e6c785db54bb3bb07fd1')throw Error('author changed');
const item=JSON.parse(execFileSync(process.execPath,[helper,origin,directory,reference,mode],{encoding:'utf8'}));
const {SecureAgentClient}=await import(pathToFileURL(reference+'/dist-workspace/src/workspace-secure-agent.js').href);
const agent=await SecureAgentClient.open({baseUrl:new URL(origin).origin,privateKey:createPrivateKey(readFileSync(item.pem_path)),statePath:item.state_path,intentDbPath:item.intent_db_path});
try {
 const before=await agent.journal(item.workspace_id),intent=agent.state.protocol_install_intents?.[item.intent_key];
 if(before.checkpoint.sequence!==item.latest_sequence||intent!==item.intent_hash||Object.keys(agent.state.pending).length)throw Error('COMPLETION_PRECONDITION');
 const wiki=before.objects.find(r=>r.kind==='instances'&&r.value.origin_entrypoint==='wiki');if(!wiki)throw Error('WIKI_MISSING');
 await agent.action(item.workspace_id,wiki.id,'wiki.create',{title:'Later staged package history',body:'Unrelated signed action after package installation END'});
 const after=await agent.journal(item.workspace_id);
 const record=after.objects.find(r=>r.kind==='records'&&r.value.payload?.title==='Later staged package history');
 if(!record||after.checkpoint.sequence!==before.checkpoint.sequence+1||after.structure?.state!=='ACTIVE'||Object.keys(agent.state.pending).length||agent.state.protocol_install_intents?.[item.intent_key]!==intent)throw Error('LATER_HISTORY_PRECONDITION');
 console.log(JSON.stringify({...item,completed_sequence:item.latest_sequence,completed_head:before.checkpoint.head,latest_sequence:after.checkpoint.sequence,latest_head:after.checkpoint.head,later_record:record,later_wiki_instance_id:wiki.id,original_intent_preserved:true}));
}finally{agent.close();}
