// Deterministic oracle inputs for the pinned TypeScript interpreter.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const source = process.env.PEERWORK_TS_SOURCE ?? fileURLToPath(new URL('reference/src/', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'peerwork-interpreter-vectors-'));
try {
  const output = join(dir, 'interpreter.mjs');
  await build({entryPoints:[resolve(source, 'workspace-interpreter.ts')], outfile:output,
    bundle:true, platform:'node', format:'esm', logLevel:'silent'});
  const {evaluateAction} = await import(pathToFileURL(output));
  const literal = value => ({from:'literal',value});
  const state = path => ({from:'state',path});
  const body = path => ({from:'body',path});
  const eq = (left,right) => ({op:'eq',left,right});
  const base = (id, variants, extras={}) => ({actions:[{id,reads:[],writes:[],
    revisionEffects:{control:true,contentEntities:[]},variants,...extras}]});
  const actorId = 'A'.repeat(43);
  const refId = 'B'.repeat(43);
  const ref = {record_id:refId,revision:1};
  const refSelector = {from:'ref',source:'state',path:['ref'],schema:'entry',scope:'INSTANCE'};
  const cases = [
    {name:'one_set',manifest:base('test.set',[{when:[eq(state(['count']),literal(0))],effects:[{op:'set',path:['count'],value:literal(1)}]}],{reads:[['count']],writes:[['count']]}),state:{count:0},body:{}},
    {name:'one_zero_effect',manifest:base('test.set',[{when:[eq(state(['count']),literal(1))],effects:[]}],{reads:[['count']],writes:[['count']]}),state:{count:1},body:{}},
    {name:'zero_variants',manifest:base('test.set',[{when:[eq(state(['count']),literal(1))],effects:[]}],{reads:[['count']],writes:[['count']]}),state:{count:2},body:{}},
    {name:'many_variants',manifest:base('test.set',[{when:[],effects:[]},{when:[],effects:[]}]),state:{},body:{}},
    {name:'exact_ref_payload',manifest:base('test.set',[{when:[{op:'exact_ref',ref:refSelector}],effects:[{op:'set',path:['result'],value:{from:'resolved_payload',ref:refSelector,path:['value']}}]}],{reads:[['ref']],writes:[['result']]}),state:{ref,result:0},body:{},exactInputs:[{recordId:refId,revision:1,schema:'entry',payload:{value:42},scope:'INSTANCE',entityId:'C'.repeat(43)}]},
    {name:'exact_ref_wrong_scope',manifest:base('test.set',[{when:[{op:'exact_ref',ref:refSelector}],effects:[]}],{reads:[['ref']]}),state:{ref},body:{},exactInputs:[{recordId:refId,revision:1,schema:'entry',payload:{value:42},scope:'WORKSPACE'}]},
    {name:'time_and_auth',manifest:base('test.set',[{when:[{op:'has_capability',capability:'clock'}],effects:[{op:'set',path:['actor'],value:{from:'auth',field:'actorId'}},{op:'set',path:['when'],value:{from:'time_add',timestamp:{from:'time'},milliseconds:literal(5)}}]}],{writes:[['actor'],['when']]}),state:{actor:'',when:0},body:{},auth:{actorId,capabilities:['clock']},executionTimeMs:1000},
    {name:'body_selector',manifest:base('test.set',[{when:[eq(body(['value']),literal('ok'))],effects:[{op:'set',path:['out'],value:body(['value'])}]}],{writes:[['out']]}),state:{out:''},body:{value:'ok'}},
    {name:'guard_set_and_numeric',manifest:base('test.set',[{when:[{op:'and',rules:[{op:'in',value:state(['count']),set:[literal(1),literal(2)]},{op:'lt',left:state(['count']),right:literal(3)},{op:'gte',left:state(['count']),right:literal(2)}]}],effects:[{op:'set',path:['out'],value:{from:'object',fields:{array:{from:'array',items:[literal('a'),state(['count'])]}}}}]}],{reads:[['count']],writes:[['out']]}),state:{count:2,out:{}},body:{}},
    {name:'guard_or_not_roles',manifest:base('test.set',[{when:[{op:'or',rules:[{op:'has_role',role:'editor'},{op:'not',rule:{op:'has_protocol_role',role:'viewer'}}]}],effects:[{op:'set',path:['out'],value:{from:'auth',field:'workspaceRoles'}}]}],{writes:[['out']]}),state:{out:[]},body:{},auth:{actorId,workspaceRoles:['editor'],protocolRoles:['viewer'],capabilities:[]}},
    {name:'append_entity_and_relation',manifest:base('test.set',[{when:[{op:'exact_ref',ref:refSelector}],effects:[{op:'append',schema:'entry',recordSlot:'created',entity:{mode:'new',slot:'entity'},selectHead:true,value:{from:'object',fields:{source:{from:'resolved_entity',ref:refSelector}}},relations:[{kind:'parent',target:refSelector},{kind:'sibling',target:{from:'produced_ref',slot:'created'}}]}]}],{reads:[['ref']],revisionEffects:{control:false,contentEntities:['entity']}}),state:{ref},body:{},exactInputs:[{recordId:refId,revision:1,schema:'entry',payload:{},scope:'INSTANCE',entityId:'C'.repeat(43)}]},
    {name:'input_contract_accept',manifest:base('test.set',[{when:[],effects:[{op:'set',path:['out'],value:body(['label'])}]}],{writes:[['out']],inputs:{fields:{label:{type:'string',maxBytes:10},count:{type:'integer',minimum:0,maximum:4},enabled:{type:'boolean'}},required:['label'],additionalProperties:false}}),state:{out:''},body:{label:'ready',count:3,enabled:true}},
    {name:'input_contract_reject',manifest:base('test.set',[{when:[],effects:[]}],{inputs:{fields:{label:{type:'string',maxBytes:2}},required:['label'],additionalProperties:false}}),state:{},body:{label:'long'}},
    {name:'invalid_write_ownership',manifest:base('test.set',[{when:[],effects:[{op:'set',path:['out'],value:literal(1)}]}]),state:{out:0},body:{}},
    {name:'exact_ref_list',manifest:base('test.set',[{when:[{op:'exact_ref_list',source:'body',path:['refs'],scope:'INSTANCE_OR_WORKSPACE',schema:'entry',max:2}],effects:[{op:'set',path:['out'],value:literal(true)}]}],{writes:[['out']]}),state:{out:false},body:{refs:[ref]},exactInputs:[{recordId:refId,revision:1,schema:'entry',payload:{},scope:'WORKSPACE'}]},
    {name:'select_head',manifest:base('test.set',[{when:[],effects:[{op:'select_head',expected:refSelector,target:refSelector}]}],{reads:[['ref']]}),state:{ref},body:{},exactInputs:[{recordId:refId,revision:1,schema:'entry',payload:{},scope:'INSTANCE'}]},
    {name:'append_entity_revise',manifest:base('test.set',[{when:[],effects:[{op:'append',schema:'entry',entity:{mode:'revise',slot:'entity',parent:refSelector},value:literal({kind:'revision'})}]}],{reads:[['ref']],revisionEffects:{control:false,contentEntities:['entity']}}),state:{ref},body:{},exactInputs:[{recordId:refId,revision:1,schema:'entry',payload:{},scope:'INSTANCE'}]},
    {name:'duplicate_action_id',manifest:{actions:[base('test.set',[{when:[],effects:[]}]).actions[0],base('test.set',[{when:[],effects:[]}]).actions[0]]},state:{},body:{}},
    {name:'undeclared_produced_slot',manifest:base('test.set',[{when:[],effects:[{op:'append',schema:'entry',value:{from:'produced_ref',slot:'missing'}}]}]),state:{},body:{}},
    {name:'duplicate_content_entity',manifest:base('test.set',[{when:[],effects:[]}],{revisionEffects:{control:false,contentEntities:['entity','entity']}}),state:{},body:{}},
    {name:'input_exact_ref',manifest:base('test.set',[{when:[],effects:[]}],{inputs:{fields:{reference:{type:'exact_ref',schema:'entry',scope:'INSTANCE'}},required:['reference'],additionalProperties:false}}),state:{},body:{reference:ref},exactInputs:[{recordId:refId,revision:1,schema:'entry',payload:{},scope:'INSTANCE'}]},
    {name:'input_enum_reject',manifest:base('test.set',[{when:[],effects:[]}],{inputs:{fields:{mode:{type:'enum',values:['on','off']}},required:['mode'],additionalProperties:false}}),state:{},body:{mode:'other'}},
    {name:'utf16_surrogate_payload',manifest:base('test.set',[{when:[],effects:[{op:'set',path:['out'],value:body(['text'])}]}],{writes:[['out']]}),state:{out:''},body:{text:'\ud800'}},
    {name:'input_nullable_accept',manifest:base('test.set',[{when:[],effects:[]}],{inputs:{fields:{label:{type:'string',nullable:true}},required:['label'],additionalProperties:false}}),state:{},body:{label:null}},
    {name:'produced_guard_rejected',manifest:base('test.set',[{when:[eq({from:'produced_ref',slot:'made'},literal(1))],effects:[{op:'append',schema:'entry',recordSlot:'made',value:literal({})}]}]),state:{},body:{}},
    {name:'missing_exact_ref_list',manifest:base('test.set',[{when:[{op:'exact_ref_list',source:'body',path:['refs'],scope:'INSTANCE',max:1}],effects:[]}]),state:{},body:{refs:[ref]}},
    {name:'action_limit_64_rejected',manifest:{actions:Array.from({length:64},(_,i)=>base(i===0?'test.set':`other.${i}`,[{when:[],effects:[]}]).actions[0])},state:{},body:{}},
    {name:'effect_limit_17_rejected',manifest:base('test.set',[{when:[],effects:Array.from({length:17},()=>({op:'set',path:['out'],value:literal(1)}))}],{writes:[['out']]}),state:{out:0},body:{}},
    {name:'utf8_max_bytes_rejected',manifest:base('test.set',[{when:[],effects:[]}],{inputs:{fields:{label:{type:'string',maxBytes:3}},required:['label'],additionalProperties:false}}),state:{},body:{label:'éé'}},
    {name:'utf8_max_bytes_accepted',manifest:base('test.set',[{when:[],effects:[]}],{inputs:{fields:{label:{type:'string',maxBytes:4}},required:['label'],additionalProperties:false}}),state:{},body:{label:'éé'}},
  ];
  for (const item of cases) {
    const args = {manifest:item.manifest,actionId:'test.set',state:item.state,body:item.body,
      auth:item.auth??{actorId,capabilities:[]},exactInputs:item.exactInputs??[],
      ...(item.executionTimeMs===undefined?{}:{executionTimeMs:item.executionTimeMs})};
    try {item.result = evaluateAction(args);} catch (error) {item.error = error.code ?? error.message;}
  }
  await writeFile(new URL('interpreter-vectors.json', import.meta.url), JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
