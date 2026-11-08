'use strict';
const sdk = require(process.argv[2]);
const fs = require('node:fs');
const x = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
(async () => {
 const options = {origin:x.origin,journalPath:x.journal,identityPath:x.identity,allowLoopbackHttp:true};
 if (x.mode === 'invalid' || x.mode === 'service') {
  try { await sdk.openKernel(options); throw new Error('unexpected success'); }
  catch(error) { if (!(error instanceof sdk.KernelError) || !(error instanceof Error) || error.code !== x.code) throw error;
   console.log(JSON.stringify({code:error.code,message:error.message,kind:error.constructor.name})); }
 } else if (x.mode === 'shape') {
  try { await sdk.openKernel({...options, transport:{requestTimeoutMs:0}}); throw new Error('unexpected success'); }
  catch(error) { if (!(error instanceof TypeError)) throw error; console.log(JSON.stringify({kind:'TypeError'})); }
 } else {
  const client=await sdk.openKernel(options);
  const p=await client.prepare(x.command);
  if(p.command_id!==x.command.command_id)throw new Error('id mismatch');
  if((await client.status(p.command_id)).state!=='PENDING')throw new Error('pending changed');
  const saved=await client.pending();if(saved.length!==1||saved[0].command_id!==p.command_id)throw new Error('saved changed');
  const result=await client.submitSaved(p.command_id);
  const fresh=await sdk.openKernel(options);
  const status=await fresh.status(p.command_id);
  const retry=await fresh.submitSaved(p.command_id);
  if(status.state!=='ACCEPTED'||JSON.stringify(result)!==JSON.stringify(retry)||result.command_id!==p.command_id)throw new Error('result changed');
  console.log(JSON.stringify({pending:p,status,result,retry}));
 }
})().catch(e=>{console.error(e);process.exitCode=1});
