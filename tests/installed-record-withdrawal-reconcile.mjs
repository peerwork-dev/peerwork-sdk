// Reconcile the original committed synthetic withdrawal after the observation
// helper assumed that every mutation creates a record. No new business intent.
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
const exec=promisify(execFile),prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX),state=resolve(process.env.PEERWORK_ACCESS_TEST_STATE),path=resolve(process.env.PEERWORK_WITHDRAWAL_RECOVERY_SOURCE),input=readFileSync(path),source=JSON.parse(input),sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk'),origin=process.env.PEERWORK_ACCESS_TEST_ORIGIN;
const before=await(await fetch(origin+'/_test/status')).json();assert.equal(source.origin,origin);const kernel=await sdk.openKernel({origin,identityPath:source.identity_path,journalPath:source.journal_path,allowLoopbackHttp:true}),result=await kernel.resumeStructureIntent(source.command_id);assert.equal(result.state,'ACCEPTED');assert.equal(result.result.structure.record_state,'WITHDRAWN');assert.equal(result.command_id??result.result.command_id,source.command_id);const python=JSON.parse((await exec(join(prefix,'python/bin/python'),['tests/installed-structure-parent.py','resume',path])).stdout);assert.equal(python.state,'ACCEPTED');assert.equal(python.command_id,source.command_id);assert.equal(python.record_id,null);const after=await(await fetch(origin+'/_test/status')).json();assert.equal(before.commands,after.commands);assert.equal(before.journalRequests,after.journalRequests);const evidence={status:'PASS',original_command_id:source.command_id,source_sha256:createHash('sha256').update(input).digest('hex'),original_receipt_reconciled:true,no_new_business_commands:true,node_and_python:true};writeFileSync(join(state,'result.json'),JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify(evidence));
