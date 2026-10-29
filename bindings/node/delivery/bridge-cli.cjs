#!/usr/bin/env node
'use strict';
// SPDX-License-Identifier: Apache-2.0
const fs=require('node:fs'),{randomBytes}=require('node:crypto');
const {serveBridge}=require('./bridge.cjs');
async function main(){
 const [command,file]=process.argv.slice(2);
 if(command==='token'){if(!file)throw Error('TOKEN_PATH_REQUIRED');fs.writeFileSync(file,randomBytes(32).toString('base64url')+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({status:'TOKEN_CREATED'}));return;}
 if(command!=='run'||!file)throw Error('Use peerwork-host-bridge token TOKEN_FILE or run CONFIG.json');
 const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o077))throw Error('BRIDGE_CONFIG_NOT_PRIVATE');
 const config=JSON.parse(fs.readFileSync(file,'utf8')),bridge=await serveBridge(config);
 console.log(JSON.stringify({status:'HOST_BRIDGE_READY',endpoint:bridge.endpoint,destination:bridge.destination}));
 let closing=false;const close=()=>{if(closing)return;closing=true;void bridge.close();};process.once('SIGTERM',close);process.once('SIGINT',close);
}
main().catch(error=>{console.error(JSON.stringify({status:'FAILED',code:error.code??(/^[A-Z_]+$/.test(error.message)?error.message:'HOST_BRIDGE_FAILED')}));process.exitCode=1;});
