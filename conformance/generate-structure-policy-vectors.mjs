// Direct policy-shape outcomes from the pinned tracked TypeScript validator.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const dir=await mkdtemp(join(tmpdir(),'peerwork-structure-policy-'));
try {
  const entry=resolve(fileURLToPath(new URL('reference/src/',import.meta.url)),'workspace-structure.ts');
  const output=join(dir,'structure.mjs');
  await build({entryPoints:[entry],outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {validateStructurePolicy}=await import(pathToFileURL(output));
  const digest='a'.repeat(64),instance='i'.repeat(43);
  const protocol={v:1,protocol_digest:digest,schemas:{'task.revision':{fields:{status:{protection:'server_readable',type:'task_status'},
    parent:{protection:'server_readable',type:'optional_reference'}},required:['status','parent']}},
    actions:{'task.create':{schemas:['task.revision'],roles:[],capabilities:[],heads:'APPEND',
      task_transition:[{from:null,to:'OPEN'}]}}};
  const valid={v:1,protocols:[protocol],disclosure:[{protocol_digest:digest,schema:'task.revision',fields:['status','parent']}],
    instances:[{instance_id:instance,protocol_digest:digest}]};
  const clone=value=>structuredClone(value);
  const cases=[
    ['empty',{v:1,protocols:[],disclosure:[],instances:[]}],
    ['task_valid',valid],
    ['null_coordination',{...valid,coordination:null}],
    ['missing_disclosure',{...valid,disclosure:[]}],
    ['bad_task_transition',(()=>{const x=clone(valid);x.protocols[0].actions['task.create'].task_transition=[{from:'MISSING',to:'OPEN'}];return x;})()],
    ['extra_protocol_field',(()=>{const x=clone(valid);x.protocols[0].extra=1;return x;})()],
    ['duplicate_instance',{...valid,instances:[...valid.instances,...valid.instances]}],
    ['unknown_action_schema',(()=>{const x=clone(valid);x.protocols[0].actions['task.create'].schemas=['missing'];return x;})()],
    ['falsy_workflow',(()=>{const x=clone(valid);x.protocols[0].schemas['task.revision'].workflow=null;return x;})()],
    ['workflow_readable',(()=>{const x=clone(valid);const schema=x.protocols[0].schemas['task.revision'];
      schema.fields.status={protection:'server_readable',type:'enum',values:['OPEN','DONE']};
      schema.workflow={v:1,status_field:'status',parent_field:'parent',states:['OPEN','DONE'],
        transitions:[{action:'task.create',from:null,to:'OPEN'}]};
      delete x.protocols[0].actions['task.create'].task_transition;return x;})()],
    ['workflow_partial_disclosure',(()=>{const x=clone(valid);const schema=x.protocols[0].schemas['task.revision'];
      schema.fields.status={protection:'server_readable',type:'enum',values:['OPEN','DONE']};
      schema.fields.parent={protection:'e2ee',type:'json'};
      schema.workflow={v:1,status_field:'status',parent_field:'parent',states:['OPEN','DONE'],
        transitions:[{action:'task.create',from:null,to:'OPEN'}]};
      delete x.protocols[0].actions['task.create'].task_transition;
      x.disclosure[0].fields=['status'];return x;})()],
  ].map(([name,input])=>{
    try {validateStructurePolicy(input);return {name,input,ok:true};}
    catch(error){return {name,input,ok:false,error:error.message};}
  });
  await writeFile(new URL('structure-policy-vectors.json',import.meta.url),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
