// Direct, deterministic tracked TypeScript secure-engine oracle cases.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const source = process.env.PEERWORK_TS_SOURCE ?? fileURLToPath(new URL('reference/src/', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'peerwork-secure-engine-vectors-'));
try {
  const output = join(dir, 'secure-engine.mjs');
  await build({entryPoints:[resolve(source, 'workspace-secure-engine.ts')], outfile:output,
    bundle:true, platform:'node', format:'esm', logLevel:'silent'});
  const {validateSecureOperation} = await import(pathToFileURL(output));
  const workspaceId = 'W'.repeat(43);
  const context = {v:1, workspace_id:workspaceId, sequence:1, action_id:'test.admin',
    instance_id:null, actor_id:'A'.repeat(43), signing_key:'K'.repeat(43)};
  const policy = {payload:{v:1, workspace_id:workspaceId, visibility:'PRIVATE', epoch:1}};
  const object = (kind, id, revision, value) => ({kind,id,revision,value,provenance:'AUTHOR_SIGNED'});
  const operation = objects => ({v:1,kind:'ADMIN',input:{},objects});
  const cases = [
    {name:'admin_empty',operation:operation([])},
    {name:'admin_workspace_create',operation:operation([object('workspaces',workspaceId,1,{id:workspaceId,workspace_id:workspaceId})])},
    {name:'admin_workspace_revision_two',operation:operation([object('workspaces',workspaceId,2,{id:workspaceId,workspace_id:workspaceId})])},
    {name:'admin_content_denied',operation:operation([object('records','r',1,{workspace_id:workspaceId})])},
    {name:'admin_cross_workspace',operation:operation([object('instances','i',1,{workspace_id:'other'})])},
    {name:'admin_prior_revision',prior:[object('instances','i',1,{workspace_id:workspaceId})],operation:operation([object('instances','i',2,{workspace_id:workspaceId})])},
  ];
  for (const item of cases) {
    item.context = context;
    item.policy = policy;
    try {await validateSecureOperation(item.operation,context,policy,item.prior??[]);item.result='ok';}
    catch (error) {item.error=error.code??error.message;}
  }
  await writeFile(new URL('secure-engine-vectors.json', import.meta.url),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
