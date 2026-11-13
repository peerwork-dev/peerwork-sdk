'use strict';
// SPDX-License-Identifier: Apache-2.0
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {AgentTools,initProfile,hash}=require('../bindings/agent-tools/tools.cjs');
const {ToolStore}=require('../bindings/agent-tools/store.cjs');
function fixture(){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'pw-original-tools-'));
 const binding={expected_actor:'alice',expected_origin:'https://example.invalid',workspace_id:'space',instance_id:'instance',protocol_digest:'a'.repeat(64),package_digest:'b'.repeat(64),role:'WORKER'};
 const profile={format:'peerwork.agent-tools.v1',kernel:{origin:binding.expected_origin,identityPath:directory+'/identity',journalPath:directory+'/journal'},binding,state_directory:directory+'/tools',contacts:{}};
 const calls=[];let outcome={state:'ACCEPTED',command_id:'original-command',result:{command_id:'original-command',event_sequence:4}};
 const kernel={actor_id:binding.expected_actor,origin:binding.expected_origin,executeStructureIntent:async intent=>{calls.push({kind:'execute',intent:structuredClone(intent)});if(outcome instanceof Error)throw outcome;return outcome;},resumeStructureIntent:async id=>{calls.push({kind:'resume',id});return outcome;},status:async id=>{calls.push({kind:'status',id});return outcome;}};
 const pin=hash({binding,identityPath:profile.kernel.identityPath,journalPath:profile.kernel.journalPath,authority:null});
 const seed=(id,{prepared=true,command=null,terminal=false}={})=>{const store=new ToolStore(profile.state_directory,pin);store.reserve(id,'frozen-input-hash',{target:{actor_id:'bob'},text:'Frozen shared message'});if(prepared)store.prepare(id,{action:'structure.action',workspace_id:'space',instance_id:'instance',protocol_digest:binding.protocol_digest,idempotency_key:'original:'+id,body:{action_id:'post',structure:{}},plaintext_contents:[{record_index:0,text:'Frozen shared message'}]});if(command||terminal)store.finish(id,{state:terminal?'ACCEPTED':'PENDING',command_id:command,effect_certainty:terminal?'COMMITTED':'UNKNOWN',target:{actor_id:'bob'}});store.close();};
 return {directory,profile,calls,seed,open:()=>new AgentTools({},kernel,profile),setOutcome:value=>{outcome=value;},cleanup:()=>fs.rmSync(directory,{recursive:true,force:true})};
}
test('retired Node entry cannot initialize a profile or a new operation store',async()=>{
 const f=fixture();try{assert.throws(()=>initProfile(f.directory+'/new.json','unused'),{code:'TOOLS_EXECUTION_RETIRED_USE_NATIVE_PARTICIPANT'});assert.throws(()=>f.open(),{code:'TOOLS_OPERATION_NOT_FOUND'});assert.equal(fs.existsSync(f.profile.state_directory),false);f.seed('old');const app=f.open();try{await assert.rejects(app.perform('send',{}, {operation_id:'new'}),{code:'TOOLS_EXECUTION_RETIRED_USE_NATIVE_PARTICIPANT'});assert.throws(()=>app.store.row('new'),{code:'TOOLS_OPERATION_NOT_FOUND'});assert.deepEqual(f.calls,[]);}finally{app.close();}}finally{f.cleanup();}
});
test('unknown historical prepared intent survives reopen without new protocol discovery or audience',async()=>{
 const f=fixture();f.seed('unknown');let app=f.open();try{f.setOutcome(Error('lost reply'));const pending=await app.recover('unknown');assert.equal(pending.effect_certainty,'UNKNOWN');assert.equal(pending.audience,'WORKSPACE_INSTANCE_SHARED');const original=f.calls[0].intent;app.close();app=f.open();f.setOutcome({state:'ACCEPTED',result:{command_id:'original-command'}});const out=await app.recover('unknown');assert.equal(out.state,'ACCEPTED');assert.deepEqual(f.calls[1],{kind:'execute',intent:original});assert.equal(original.idempotency_key,'original:unknown');assert.equal(out.model_response,'NOT_ATTESTED');}finally{app.close();f.cleanup();}
});
test('known historical command resumes its original ID and never resubmits a prepared intent',async()=>{
 const f=fixture();f.seed('saved',{command:'exact-native-command'});const app=f.open();try{f.setOutcome({state:'ACCEPTED',result:{command_id:'exact-native-command'}});assert.equal((await app.recover('saved')).command_id,'exact-native-command');assert.deepEqual(f.calls,[{kind:'resume',id:'exact-native-command'}]);}finally{app.close();f.cleanup();}
});
test('old unprepared reservation remains unsubmitted without reconstructing a business action',async()=>{
 const f=fixture();f.seed('reserved',{prepared:false});const app=f.open();try{const out=await app.recover('reserved');assert.equal(out.state,'NOT_SUBMITTED');assert.equal(out.code,'TOOLS_ORIGINAL_OPERATION_NOT_PREPARED');assert.deepEqual(f.calls,[]);assert.equal(app.store.row('reserved').input.text,'Frozen shared message');}finally{app.close();f.cleanup();}
});
test('terminal old outcome is observed without network and status does not replace an unknown command',async()=>{
 const f=fixture();f.seed('done',{command:'terminal',terminal:true});f.seed('pending',{command:'unknown'});const app=f.open();try{assert.equal((await app.recover('done')).state,'ACCEPTED');f.setOutcome({state:'NOT_FOUND'});assert.equal((await app.status('pending')).effect_certainty,'UNKNOWN');assert.deepEqual(f.calls,[{kind:'status',id:'unknown'}]);}finally{app.close();f.cleanup();}
});
test('changed original binding cannot open the historical operation namespace',()=>{
 const f=fixture();f.seed('saved');try{f.profile.binding.workspace_id='different';assert.throws(()=>f.open(),{code:'TOOLS_PROFILE_MISMATCH'});assert.deepEqual(f.calls,[]);}finally{f.cleanup();}
});
