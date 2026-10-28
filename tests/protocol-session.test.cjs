// SPDX-License-Identifier: Apache-2.0
const test = require('node:test');
const assert = require('node:assert/strict');
const {createProtocolSession} = require('../bindings/node/protocol-session.cjs');
const clone = v => JSON.parse(JSON.stringify(v));
const binding = {expected_origin:'https://api.peerwork.dev',expected_actor:'alice',workspace_id:'space',instance_id:'instance',protocol_digest:'a'.repeat(64),package_digest:'b'.repeat(64),role:'WORKER'};
function fixture() {
  const calls=[],kernel={actor_id:'alice',origin:binding.expected_origin,executeStructureIntent:async i=>{calls.push(clone(i));return {state:'PENDING',command_id:'original',code:'RATE_LIMITED',effect_certainty:'UNKNOWN',recovery:'RESUME_SAME_INTENT'};}};
  let outcome={state:'ACCEPTED',result:{workspace_id:'space',instance_id:'instance',protocol_digest:binding.protocol_digest,structure:{workspace_id:'space',package_digest:binding.package_digest,protocol_digest:binding.protocol_digest,evidence:{binding:{instance_id:'instance'}},resources:{'worker.md':{content:'Read exact versions.'}},runtime:{actor_id:'alice',role:'WORKER',instructions_resource:'worker.md',context:['selected_state'],tools:[{name:'correct',action:'finding.correct',input_schema:{fields:{previous:{type:'exact_ref'},related:{type:'exact_ref'},summary:{type:'string'}}}}]}}}};
  const session=createProtocolSession(kernel,binding,{snapshot:clone,protocols:()=>({role:async q=>{calls.push(clone(q));return clone(outcome);}})});
  return {session,kernel,calls,setOutcome:v=>{outcome=v;}};
}
test('bounded reads do not drain pages or manufacture successful outcomes',async()=>{
 const {session,calls}=fixture();
 const out=await session.records();assert.equal(out.command_id,'original');assert.equal(out.effect_certainty,'UNKNOWN');assert.equal(calls.length,1);assert.equal(calls[0].body.limit,16);
 await session.updates({after_sequence:12,limit:2});assert.deepEqual(calls[1].body,{after_sequence:12,limit:2});
 for(const q of [{limit:33},{limit:0},{cursor:'a',after_sequence:1},{workspace_id:'foreign'},{limit:1.5}])assert.throws(()=>session.records(q),/PROTOCOL_PAGE_INVALID/);
 assert.equal(calls.length,2);
});
test('role tools bind exact refs; returned objects cannot mutate selection or cached grants',async()=>{
 const {session,calls}=fixture();
 assert.throws(()=>session.prepareAction({}),/PROTOCOL_CONTEXT_REQUIRED/);
 const d=await session.describe();d.context.tools[0].action='evil';d.context.binding.workspace_id='foreign';
 const request={tool:'correct',values:{previous:{record_id:'r',revision:2},related:{record_id:'r',revision:2},summary:'Updated'},expected_revision:7,operation_id:'one-operation'};
 const prepared=session.prepareAction(request);assert.equal(prepared.intent.body.action_id,'finding.correct');assert.deepEqual(prepared.intent.exact_input_refs,[{record_id:'r',revision:2}]);
 request.values.summary='Changed';assert.equal(prepared.intent.body.structure.summary,'Updated');
 const out=await session.submit(prepared);assert.equal(out.state,'PENDING');await session.resume(clone(prepared));
 assert.deepEqual(calls.at(-1),calls.at(-2));assert.equal(calls.at(-1).expected_instance_revision,7);
 assert.throws(()=>session.prepareAction({...request,action_id:'anything'}),/PROTOCOL_ACTION_INVALID/);
 assert.throws(()=>session.prepareAction({...request,tool:'not-granted'}),/PROTOCOL_ACTION_NOT_GRANTED/);
 assert.throws(()=>session.prepareAction({...request,values:{previous:{record_id:'r',revision:0}}}),/PROTOCOL_REFERENCE_INVALID/);
});
test('cross-actor, cross-package and cross-instance selections fail before submission',async()=>{
 const f=fixture();await f.session.describe();
 const p=f.session.prepareAction({action_id:'finding.correct',values:{previous:{record_id:'r',revision:1}},expected_revision:1,operation_id:'original'});
 for(const key of Object.keys(binding)){
  const changed=clone(p);changed.binding[key]='foreign';await assert.rejects(f.session.resume(changed),/PROTOCOL_BINDING_MISMATCH/);
 }
 assert.equal(f.calls.length,1);
 const bad=fixture();bad.setOutcome({state:'ACCEPTED',result:{structure:{workspace_id:'space',protocol_digest:binding.protocol_digest,package_digest:'c'.repeat(64)}}});
 await assert.rejects(bad.session.describe(),/PROTOCOL_BINDING_MISMATCH/);
 assert.throws(()=>bad.session.prepareAction({}),/PROTOCOL_CONTEXT_REQUIRED/);
 f.kernel.actor_id='bob';await assert.rejects(f.session.state(),/PROTOCOL_BINDING_MISMATCH/);
});
