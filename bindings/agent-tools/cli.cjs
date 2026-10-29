#!/usr/bin/env node
'use strict';
// SPDX-License-Identifier: Apache-2.0
const fs=require('node:fs'),path=require('node:path'),{spawn}=require('node:child_process');
const {AgentTools,initProfile,loadProfile,localState}=require('./tools.cjs'),{privateFile,fail}=require('./store.cjs');
const usage=`peerwork-agent [--profile /private/profile.json] COMMAND
  init --from-receiver /private/receiver.json
  contact ALIAS --actor ACTOR --send-tool TOOL --values /private/defaults.json
    [--reply-tool TOOL --reply-ref FIELD --reply-values /private/defaults.json]
  protocol [--refresh | --full]
  send ALIAS [--id OPERATION_ID] [--text-file FILE]       (otherwise stdin)
  reply ALIAS RECORD@REV [--id OPERATION_ID] [--text-file FILE]
  action TOOL --values FILE [--id OPERATION_ID] [--expected-revision N] [--text-file FILE]
  status OPERATION_ID [--local]
  recover OPERATION_ID
  operations [--after ID] [--limit 16]
  records [--cursor CURSOR] [--limit 16] [--schema SCHEMA]
  updates [--after-sequence N | --cursor CURSOR] [--limit 16]
  record RECORD@REV
  listen | doctor | connection
  version
Select a profile explicitly or with PEERWORK_PROFILE. No implicit identity lookup.
Messages are protocol actions in a shared instance, not private direct messages.`;
function argumentsOf(argv){const named={},pos=[];for(let i=0;i<argv.length;i++){const a=argv[i];if(a.startsWith('--')){if(Object.hasOwn(named,a))fail('TOOLS_ARGUMENT_INVALID');if(['--help','--full','--refresh','--local'].includes(a))named[a]=true;else{if(!argv[i+1]||argv[i+1].startsWith('--'))fail('TOOLS_ARGUMENT_INVALID');named[a]=argv[++i];}}else pos.push(a);}return {named,pos};}
function allowed(named,keys){for(const k of Object.keys(named))if(!['--profile',...keys].includes(k))fail('TOOLS_ARGUMENT_INVALID');}
async function stdin(){if(process.stdin.isTTY)fail('TOOLS_BODY_REQUIRED');let bytes=0,parts=[];for await(const chunk of process.stdin){bytes+=chunk.length;if(bytes>16384)fail('TOOLS_BODY_INVALID');parts.push(chunk);}return new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts));}
async function body(named){return named['--text-file']?new TextDecoder('utf-8',{fatal:true}).decode(Buffer.from(privateFile(path.resolve(named['--text-file']),16384))):stdin();}
function values(file){const v=JSON.parse(privateFile(path.resolve(file),65536));if(!v||typeof v!=='object'||Array.isArray(v))fail('TOOLS_VALUES_INVALID');return v;}
async function main(){
 const {named,pos}=argumentsOf(process.argv.slice(2)),[command,...args]=pos;if(named['--help']||command==='help'||!command){console.log(usage);return;}
 if(Number(process.versions.node.split('.')[0])<24)fail('TOOLS_REQUIRE_NODE_24');
 if(command==='version'){allowed(named,[]);if(args.length)fail('TOOLS_ARGUMENT_INVALID');console.log(JSON.stringify({tool:'peerwork-agent',version:require('./package.json').version,sdk_version:require('@peerwork/agent-sdk').version(),node:process.versions.node}));return;}
 const file=named['--profile']??process.env.PEERWORK_PROFILE;if(!file)fail('TOOLS_PROFILE_REQUIRED');
 if(command==='init'){allowed(named,['--from-receiver']);if(args.length||!named['--from-receiver'])fail('TOOLS_ARGUMENT_INVALID');console.log(JSON.stringify(initProfile(file,named['--from-receiver'])));return;}
 if(command==='contact'){
  allowed(named,['--actor','--send-tool','--values','--reply-tool','--reply-ref','--reply-values']);if(args.length!==1||!named['--actor']||!named['--send-tool']||!named['--values'])fail('TOOLS_ARGUMENT_INVALID');
  const p=loadProfile(file),contact={actor_id:named['--actor'],send:{tool:named['--send-tool'],values:values(named['--values'])}};
  if(named['--reply-tool']||named['--reply-ref']||named['--reply-values']){if(!named['--reply-tool']||!named['--reply-ref']||!named['--reply-values'])fail('TOOLS_ARGUMENT_INVALID');contact.reply={tool:named['--reply-tool'],reference_field:named['--reply-ref'],values:values(named['--reply-values'])};}
  p.contacts={...p.contacts,[args[0]]:contact};const temporary=file+'.'+require('node:crypto').randomUUID()+'.new';try{fs.writeFileSync(temporary,JSON.stringify(p,null,2)+'\n',{flag:'wx',mode:0o600});loadProfile(temporary);fs.renameSync(temporary,file);}finally{if(fs.existsSync(temporary))fs.unlinkSync(temporary);}console.log(JSON.stringify({state:'CONTACT_CONFIGURED',alias:args[0],actor_id:contact.actor_id,audience:'WORKSPACE_INSTANCE_SHARED'}));return;
 }
 if(['listen','doctor','connection'].includes(command)){
  allowed(named,[]);if(args.length)fail('TOOLS_ARGUMENT_INVALID');const p=loadProfile(file);if(!p.connector_config)fail('TOOLS_CONNECTOR_NOT_CONFIGURED');const receiver=JSON.parse(privateFile(p.connector_config));
  // A changed receiver file must never silently select a different identity/space.
  const {hash}=require('./tools.cjs');if(hash(receiver.binding)!==hash(p.binding)||hash(receiver.kernel)!==hash(p.kernel))fail('TOOLS_PROFILE_MISMATCH');
  const sdk=require.resolve('@peerwork/agent-sdk'),cli=path.join(path.dirname(sdk),'delivery/cli.cjs'),child=spawn(process.execPath,[cli,command==='listen'?'run':command==='connection'?'status':'doctor',p.connector_config],{stdio:'inherit'});
  process.once('SIGTERM',()=>child.kill('SIGTERM'));process.once('SIGINT',()=>child.kill('SIGINT'));const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve);});process.exitCode=code??1;return;
 }
 const options={protocol:['--refresh','--full'],send:['--id','--text-file'],reply:['--id','--text-file'],action:['--id','--values','--text-file','--expected-revision'],status:['--local'],recover:[],operations:['--after','--limit'],records:['--cursor','--limit','--schema'],updates:['--cursor','--limit','--after-sequence'],record:[]};
 if(!Object.hasOwn(options,command))fail('TOOLS_COMMAND_UNKNOWN');allowed(named,options[command]);const counts={send:1,reply:2,action:1,status:1,recover:1,record:1};if(args.length!==(counts[command]??0))fail('TOOLS_ARGUMENT_INVALID');
 if(command==='operations'||command==='status'&&named['--local']){const out=localState(file,command==='operations'?{after:named['--after']??'',limit:Number(named['--limit']??16)}:{operation_id:args[0]});console.log(JSON.stringify(out));if(out.state==='PENDING')process.exitCode=2;else if(out.state==='REJECTED')process.exitCode=3;return;}
 const app=await AgentTools.open(file);try{
  let out;
  if(command==='protocol')out=named['--full']?await app.inspect():await app.context(Boolean(named['--refresh']));
  if(['send','reply','action'].includes(command)){
   if(command==='action'&&!named['--values'])fail('TOOLS_VALUES_REQUIRED');
   const text=command==='action'&&!named['--text-file']?undefined:await body(named);
   out=await app.perform(command,{...(command==='action'?{tool:args[0],values:values(named['--values'])}:{to:args[0]}),...(text===undefined?{}:{text}),...(command==='reply'?{reply_to:args[1]}:{}),...(named['--expected-revision']?{expected_revision:Number(named['--expected-revision'])}:{})},{...(named['--id']?{operation_id:named['--id']}:{}),onReserved:v=>process.stderr.write(JSON.stringify(v)+'\n')});
  }
  if(command==='status')out=await app.status(args[0],{delivery:!named['--local'],refresh:!named['--local']});
  if(command==='recover')out=await app.recover(args[0]);
  if(command==='operations')out=app.operations(named['--after']??'',Number(named['--limit']??16));
  if(command==='record')out=await app.record(args[0]);
  if(command==='records'||command==='updates'){const query={limit:Number(named['--limit']??16),...(named['--cursor']?{cursor:named['--cursor']}:{}),...(named['--schema']?{schema:named['--schema']}:{}),...(named['--after-sequence']?{after_sequence:Number(named['--after-sequence'])}:{})};out=await app[command](query);}
  console.log(JSON.stringify(out));if(out?.state==='PENDING')process.exitCode=2;else if(out?.state==='REJECTED')process.exitCode=3;
 }finally{app.close();}
}
main().catch(error=>{console.error(JSON.stringify({state:'FAILED',code:/^[A-Z][A-Z0-9_]{2,100}$/.test(error.code??'')?error.code:'TOOLS_FAILED',...(error.outcome?{outcome:error.outcome}:{}),recovery:error.outcome?.recovery??'If an operation ID was reserved, use it with recover; never replace an unknown submission.'}));process.exitCode=1;});
