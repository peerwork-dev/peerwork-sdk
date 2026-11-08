// Public installed Node API adapter; Python interpreter prefixes are hidden.
const fs=require('node:fs');const root=process.env.PEERWORK_TEST_SDK_ROOT;
if(fs.existsSync('/opt/python/cp311-cp311/bin/python')||fs.existsSync('/usr/local/bin/python3.12'))throw Error('PYTHON_PRESENT');
const pkg=root+'/dist/node-consumer/node_modules/@peerwork/agent-sdk';const sdk=require(pkg);if(!require.resolve(pkg).startsWith(root+'/dist/node-consumer/'))throw Error('WRONG_MODULE');
const r=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),c=r.config,op=r.op,x=r.input??{},w=r.workspace,id=r.command;
const camel=o=>Object.fromEntries(Object.entries(o).map(([k,v])=>[k.replace(/_([a-z])/g,(_,a)=>a.toUpperCase()),v]));const cfg=camel(c),o=sdk.openSecureOwnerWorkspaces(cfg);const action=()=>op.startsWith('member-')?sdk.openSecurePublicActions(cfg):o.publicActions(w);
(async()=>{let v;
if(op==='runtime'){const crypto=require('node:crypto'),native=Object.keys(require.cache).find(p=>p.endsWith('.node'));if(!native||!native.startsWith(root+'/dist/node-consumer/'))throw Error('WRONG_NATIVE');v={module:require.resolve(pkg),native,wrapper_sha256:crypto.createHash('sha256').update(fs.readFileSync(require.resolve(pkg))).digest('hex'),native_sha256:crypto.createHash('sha256').update(fs.readFileSync(native)).digest('hex'),executable:process.execPath,python_absent:true};}
else if(op==='prepare')v=await o.prepare({name:'Independent official business',visibility:'PUBLIC',structured:true});
else if(op==='resume')v=await o.resume(id);
else if(op==='identity')v=await sdk.openIdentity(c.state_dir+'/identity.state');
else if(op==='owner-read')v=await o.read(w);
else if(op==='install-begin')v=await o.publicInstaller(w).begin(camel(x));
else if(op==='install-continue')v=await o.publicInstaller(w).continueInstall(id);
else if(op.endsWith('-submit'))v=await action().submit(x.action_id,x.instance_id,x.body,{exactInputRefs:x.exact_input_refs,commandId:x.command_id});
else if(op.endsWith('-status'))v=await action().reconcile(id);
else if(op.endsWith('-retry'))v=await action().retrySaved(id);
else if(op==='recipient-create')v=await sdk.openSecureRecipientEnrollment(cfg).createLocal();
else if(op==='recipient-publish')v=await sdk.openSecureRecipientEnrollment(cfg).publish();
else if(op==='lookup')v=await sdk.openSecureIdentityDirectory(cfg).lookup(x.actor_id,x.key_id);
else if(op==='offer')v=await o.publicAdmission(w).offer(x.certificate_json,x.scopes,{message:'Adopt exact proposal'});
else if(op==='deliver')v=await o.publicAdmission(w).deliver(id);
else if(op==='delivery-resume')v=await o.publicAdmission(w).retryDelivery(id);
else if(op==='consent')v=await sdk.openSecureInvitation(cfg).decide(id,'ACCEPT');
else if(op==='receive')v=await sdk.openSecureInvitation(cfg).receive(id);
else if(op==='receive-resume')v=await sdk.openSecureInvitation(cfg).retryReceive(id);
else if(op==='member-read')v=await sdk.readSecureWorkspace(cfg);
else throw Error('UNKNOWN_OPERATION');console.log(JSON.stringify(v));})().catch(e=>{console.error(JSON.stringify({code:e.code??'ADAPTER_ERROR',message:e.message}));process.exitCode=1});
