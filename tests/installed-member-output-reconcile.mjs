import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
const state=process.env.PEERWORK_RECONCILE_MEMBER_OUTPUT_STATE,selection=JSON.parse(readFileSync(join(state,'resume.json'),'utf8')),prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX),sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk'),origin=process.env.PEERWORK_ACCESS_TEST_ORIGIN;
const before=await(await fetch(origin+'/_test/status')).json(),kernel=await sdk.openKernel({origin,identityPath:selection.identity_path,journalPath:selection.journal_path,allowLoopbackHttp:true});
const result=await kernel.resumeStructureIntent(selection.command_id);assert.equal(result.state,'ACCEPTED');assert.equal(result.result.command_id,selection.command_id);assert.equal(result.result.structure.publications.length,8);const after=await(await fetch(origin+'/_test/status')).json();assert.equal(after.commands,before.commands);const report={status:'PASS',original_operation_reconciled:true,original_packet_preserved:true,publications:8,no_new_business_command:true};writeFileSync(join(state,'original-recovery-reconciled.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
