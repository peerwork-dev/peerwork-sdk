import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {installWorkflows} from './workflow.mjs';

// Run inside a project with @peerwork/agent-sdk 0.2.3 installed.
const sdk=createRequire(resolve('package.json'))('@peerwork/agent-sdk');
const config=JSON.parse(readFileSync(process.argv[2],'utf8'));
const client=await sdk.openKernel(config.client);
const result=await installWorkflows(client,config,process.argv[3]);
console.log(JSON.stringify({workspace_id:result.workspace_id,instances:result.instances,grants:result.grants}));
