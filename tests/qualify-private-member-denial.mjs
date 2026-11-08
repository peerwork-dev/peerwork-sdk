// Offline discriminator only: no signing, transport, grants, or journal writes.
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
const [modules,readPath,policyPath,fixturePath,outputPath]=process.argv.slice(2);
assert.ok(modules&&readPath&&policyPath&&fixturePath&&outputPath);
const {prepareSecureAction}=await import(pathToFileURL(resolve(modules,'workspace-secure-engine.js')));
const {createActionContext,secureHash}=await import(pathToFileURL(resolve(modules,'workspace-secure-client.js')));
const view=JSON.parse(readFileSync(readPath,'utf8')),policy=JSON.parse(readFileSync(policyPath,'utf8')),fixture=JSON.parse(readFileSync(fixturePath,'utf8'));
assert.equal(await secureHash(policy),view.policy_hash);
assert.equal(policy.payload.workspace_id,fixture.workspace_id);
assert.equal(view.sequence,fixture.node_expected_sequence);
const member=policy.payload.members.find(m=>m.actor_id===fixture.member_actor_id);
assert.ok(member);
const denial=fixture.denial;
assert.equal(denial.action_id,'wiki.revise');
const checkpoint={v:1,workspace_id:fixture.workspace_id,owner_id:policy.payload.owner_id,owner_key:policy.payload.signing_key,sequence:view.sequence,head:view.head,policy_hash:view.policy_hash};
const common={policy,checkpoint,actionId:denial.action_id,instanceId:denial.instance_id,commandId:denial.command_id,issuedAt:Date.now()};
const prepare=async identity=>prepareSecureAction({objects:view.objects,policy,context:await createActionContext({...common,identity}),body:denial.body,exactRefs:[{record_id:denial.record_id,revision:denial.revision}]});
let memberCode;
try { await prepare({actorId:member.actor_id,keyId:member.certificate.payload.signing_key}); }
catch(error){ memberCode=error.code; }
assert.equal(memberCode,'AUTHOR_SCOPE_DENIED');
const ownerOperation=await prepare({actorId:policy.payload.owner_id,keyId:policy.payload.signing_key});
assert.equal(ownerOperation.kind,'ACTION');
const result={status:'PASS',scope:'offline reference-engine qualification of the same signed policy, verified objects, action body and exact reference; not a native detailed-error or server-403 observation',policy_hash:view.policy_hash,sequence:view.sequence,member_code:memberCode,owner_same_input_prepares:true,action_id:denial.action_id,network_calls:0,signed_or_submitted_operations:0};
writeFileSync(outputPath,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify(result));
