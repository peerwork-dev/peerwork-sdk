#!/usr/bin/env node
'use strict';
// SPDX-License-Identifier: Apache-2.0
// Compatibility recovery only. Ordinary work uses the native Participant tools.
const {AgentTools,localState}=require('./tools.cjs');
const {fail}=require('./store.cjs');
const usage=`Historical peerwork-agent operation recovery:
  peerwork-agent --profile ORIGINAL_PROFILE status ORIGINAL_ID [--local]
  peerwork-agent --profile ORIGINAL_PROFILE recover ORIGINAL_ID
  peerwork-agent --profile ORIGINAL_PROFILE operations [--after ID] [--limit 16]
New work uses native peerwork tools on the original Participant client.
Keep old stores and command IDs; historical shared messages stay shared.`;
async function main(){
 const args=process.argv.slice(2),named={},pos=[];
 for(let i=0;i<args.length;i++){const a=args[i];if(a.startsWith('--')){if(Object.hasOwn(named,a))fail('TOOLS_ARGUMENT_INVALID');if(['--help','--local'].includes(a))named[a]=true;else{if(!args[i+1]||args[i+1].startsWith('--'))fail('TOOLS_ARGUMENT_INVALID');named[a]=args[++i];}}else pos.push(a);}
 const [command,id]=pos;if(!command||named['--help']){console.log(usage);return;}
 if(!['status','recover','operations','version'].includes(command))fail('TOOLS_EXECUTION_RETIRED_USE_NATIVE_PARTICIPANT');
 if(command==='version'){console.log(JSON.stringify({tool:'peerwork-agent',version:require('./package.json').version,mode:'ORIGINAL_OPERATION_RECOVERY_ONLY'}));return;}
 for(const k of Object.keys(named))if(!['--profile',...(command==='status'?['--local']:command==='operations'?['--after','--limit']:[])].includes(k))fail('TOOLS_ARGUMENT_INVALID');
 if(pos.length!==(command==='operations'?1:2))fail('TOOLS_ARGUMENT_INVALID');
 const file=named['--profile']??process.env.PEERWORK_PROFILE;if(!file)fail('TOOLS_PROFILE_REQUIRED');
 if(command==='operations'||named['--local']){console.log(JSON.stringify(localState(file,command==='operations'?{after:named['--after']??'',limit:Number(named['--limit']??16)}:{operation_id:id})));return;}
 const app=await AgentTools.open(file);try{const out=await app[command](id);console.log(JSON.stringify(out));if(out.state==='PENDING')process.exitCode=2;else if(out.state==='REJECTED')process.exitCode=3;}finally{app.close();}
}
main().catch(error=>{console.error(JSON.stringify({state:'FAILED',code:error.code??'TOOLS_FAILED',recovery:'Use the original operation ID for recovery; new work uses native Participant tools.'}));process.exitCode=1;});
