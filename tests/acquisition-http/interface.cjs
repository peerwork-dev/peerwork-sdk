// Operator-synthetic installed Node consumer; only supported public SDK calls.
'use strict';
const fs=require('node:fs');
const sdk=require(process.env.PEERWORK_TEST_NODE_PACKAGE);
const [operation,inputFile]=process.argv.slice(2);
const input=JSON.parse(fs.readFileSync(inputFile,'utf8'));
const {config:c,arg:a,observationsPath}=input;
const options={origin:c.origin,stateDir:c.state_dir,identityPath:c.identity_path,
 workspaceId:c.workspace_id,ownerActorId:c.owner_actor_id,ownerKeyId:c.owner_key_id,
 authority:c.authority,allowLoopbackHttp:true};
const observer=()=>sdk.openAcquisitionObservations({path:observationsPath});
(async()=>{
 let result;
 switch(operation){
 case 'identity-info':result=await sdk.openIdentity(c.identity_path);break;
 case 'identity-import':result=await sdk.importLegacyOwnerIdentity(a.config_file,a.pem_file);break;
 case 'read':result=await sdk.openSecurePublicActions(options).read();break;
 case 'catalog-search':result=await sdk.openPublicCatalog({origin:a.origin,allowLoopbackHttp:true}).search('proposal');break;
 case 'catalog-inspect':result=await sdk.openPublicCatalog({origin:a.origin,allowLoopbackHttp:true}).inspectExact(a.digest);break;
 case 'install-begin':result=await sdk.openSecurePublicPackageInstaller(options).begin({closureJson:a.closure_json,
 expectedPackageId:a.expected_package_id,expectedPackageVersion:a.expected_package_version,
 expectedPackageDigest:a.expected_package_digest,expectedProtocolDigest:a.expected_protocol_digest,
 instanceId:a.instance_id,entrypoint:a.entrypoint,grantsJson:a.grants_json});break;
 case 'install-continue':result=await sdk.openSecurePublicPackageInstaller(options).continueInstall(a.command_id);break;
 case 'install-pending':result=await sdk.openSecurePublicPackageInstaller(options).pending();break;
 case 'action-submit':result=await sdk.openSecurePublicActions(options).submit('proposal.propose',a.instance_id,a.body,{commandId:a.command_id});break;
 case 'action-status':result=await sdk.openSecurePublicActions(options).reconcile(a.command_id);break;
 case 'action-retry':result=await sdk.openSecurePublicActions(options).retrySaved(a.command_id);break;
 case 'append':result=await observer().append(a);break;
 case 'catalog-result':result=await observer().recordCatalogResult(a.event,a.result);break;
 case 'install-result':result=await observer().recordInstallResult(a);break;
 case 'action-result':result=await observer().recordActionResult(a.event,a.selected_instance_id,a.result_instance_id,a.result);break;
 case 'export':result=await observer().export();break;
 case 'scorecard':result=await observer().scorecard(a);break;
 case 'snapshots':result=await observer().snapshots();break;
 default:throw new Error('unsupported fixture operation');
 }
 console.log(JSON.stringify({ok:true,value:result}));
})().catch(error=>{console.log(JSON.stringify({ok:false,code:error.code||'FIXTURE_CLIENT_FAILED'}));process.exitCode=1;});
