import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {join,resolve} from 'node:path';
import {writeFileSync} from 'node:fs';
const prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX),sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk'),origin=process.env.PEERWORK_ACCESS_TEST_ORIGIN,path=process.env.PEERWORK_RECONCILE_SNAPSHOT_STATE;
const before=await(await fetch(origin+'/_test/status')).json(),kernel=await sdk.openKernel({origin,identityPath:join(path,'owner/identity'),journalPath:join(path,'owner/operations.sqlite'),allowLoopbackHttp:true});
const outcome=await kernel.resumeStructureIntent('twMAKNIGMgdZq6toF6pt-q9e6iGxwWvDOu5HapHvSwI');assert.equal(outcome.state,'ACCEPTED');assert.equal(outcome.result.command_id,'twMAKNIGMgdZq6toF6pt-q9e6iGxwWvDOu5HapHvSwI');assert.equal(outcome.result.structure.publication_revision,5);const after=await(await fetch(origin+'/_test/status')).json();assert.equal(after.publicationPrepareReads,before.publicationPrepareReads);assert.equal(after.commands,before.commands);
const result={status:'PASS',original_operation_reconciled:true,publication_revision:5,no_new_preparation:true,no_new_mutation:true};writeFileSync(join(path,'original-recovery-reconciled.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));
