// Genuine public author/staging/install/history only; source files and DB are not edited.
import{generateKeyPairSync,randomBytes}from'node:crypto';import{mkdirSync,writeFileSync}from'node:fs';import{join}from'node:path';import{pathToFileURL}from'node:url';
import{combinedMaterial}from'./material.mjs';import{createLegacyComposedInstallMaterial as nestedMaterial}from'../installed-nested-package/material.mjs';
const[origin,dir,reference,mode]=process.argv.slice(2);if(!['combined','implicit-later','temporal-negative','object-later'].includes(mode))throw Error('INPUT');
mkdirSync(dir,{recursive:true,mode:0o700});const load=n=>import(pathToFileURL(reference+'/dist-workspace/src/'+n+'.js').href);
const{SecureAgentClient}=await load('workspace-secure-agent');const{secureHash,secureEqual}=await load('workspace-secure-client');const{resolveProtocolInstall}=await load('workspace-protocol-install-plan');
const privateKey=generateKeyPairSync('ed25519').privateKey;const paths={state_path:join(dir,'agent.state'),pem_path:join(dir,'owner.pem'),intent_db_path:join(dir,'workspace-intents.sqlite'),options_path:join(dir,'install-options.json'),material_path:join(dir,'install-material.json')};writeFileSync(paths.pem_path,privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
const agent=await SecureAgentClient.open({baseUrl:new URL(origin).origin,privateKey,statePath:paths.state_path,intentDbPath:paths.intent_db_path});
try{
 const workspace=(await agent.create('Residual source boundary', 'PRIVATE',{structure:true})).workspaceId;let prior=await agent.journal(workspace);
 const selected=mode==='combined'?await combinedMaterial(reference):mode==='object-later'?{material:await(await import('../legacy-owner-install-object-material.mjs')).createLegacyObjectInstallMaterial(reference)}:await nestedMaterial(reference),material=selected.material;
 const compiled=mode==='combined'?selected.compiled:mode==='object-later'?await(await load('workspace-protocol-package-source')).compilePackageMaterial(material):{manifest:selected.compiledManifest,protocolDigest:selected.protocolDigest};
 writeFileSync(paths.material_path,JSON.stringify(material),{mode:0o600,flag:'wx'});
 const instance=randomBytes(32).toString('base64url'),key=workspace+'.'+instance;let options,packageProof;
 if(mode==='combined'){
  const staged=await agent.stagePackageMaterial(workspace,material,prior.checkpoint);packageProof=staged.proof;
  options={instance_id:instance,entrypoint:'combined_source',manifest:compiled.manifest,grants:[],expected_checkpoint:prior.checkpoint,package_source:packageProof};
 }else if(mode==='object-later'){options={instance_id:instance,entrypoint:'object_source',manifest:compiled.manifest,grants:[],expected_checkpoint:prior.checkpoint};
 }else{
  const dep=selected.dependencies[0];
  if(mode==='implicit-later'){
   await agent.installProtocol(workspace,{instance_id:randomBytes(32).toString('base64url'),entrypoint:'authenticated_dependency',manifest:dep.manifest,grants:[]});prior=await agent.journal(workspace);
   if(!prior.objects.some(r=>r.kind==='protocols'&&r.id===dep.digest))throw Error('PRIOR_DEPENDENCY');
  }else if(prior.objects.some(r=>r.kind==='protocols'&&r.id===dep.digest))throw Error('UNEXPECTED_PRIOR_DEPENDENCY');
  options={instance_id:instance,entrypoint:'nested_selected',manifest:selected.sourceManifest,...(mode==='temporal-negative'?{dependencies:selected.dependencies}:{}),grants:[]};
 }
 const resolved=await resolveProtocolInstall(await agent.journal(workspace),options,agent.transport.discovery.protocol_features??[]);
 const originalPost=agent.post.bind(agent),originalRequest=agent.request.bind(agent);let stopped=false,originalBeginId;
 if(mode==='combined')agent.request=async(path,request)=>{if(!stopped&&request?.method==='POST'&&JSON.parse(request.body).commit?.payload?.action_id==='secure.structure.begin'){stopped=true;throw Error('STOP_BEFORE_COMBINED_BEGIN');}return originalRequest(path,request);};
 else agent.post=async(...args)=>{if(args[1]?.commit?.payload?.action_id==='secure.structure.begin')originalBeginId=args[1].commit.payload.command_id;const result=await originalPost(...args);if(!stopped&&args[1]?.commit?.payload?.action_id==='secure.structure.end'){stopped=true;throw Error('STOP_AFTER_END');}return result;};
 try{await agent.installProtocol(workspace,options);throw Error('NOT_STOPPED');}catch(e){if(!stopped||!['STOP_BEFORE_COMBINED_BEGIN','STOP_AFTER_END'].includes(e.message))throw e;}finally{agent.post=originalPost;agent.request=originalRequest;}
 let journal=await agent.journal(workspace);const completedSequence=journal.checkpoint.sequence,completedHead=journal.checkpoint.head;
 if(agent.state.protocol_install_intents?.[key]!==resolved.intentHash)throw Error('ORIGINAL_INTENT');
 let extra={};
 if(mode==='combined'){
  const marker=agent.state.protocol_object_stage_intents?.[key];if(!marker||!marker.proof||marker.parts.length<2)throw Error('OBJECT_PROOF');
  const{readProtocolPackageMaterial,verifyStagedPackageCheckpoint}=await load('workspace-protocol-package-source');const{readProtocolObjectSource,verifyStagedProtocolObjectCheckpoint}=await load('workspace-protocol-object-source').then(async m=>({...m,...await load('workspace-protocol-object-stage')}));
  if(!secureEqual(readProtocolPackageMaterial(packageProof,journal.objects),material))throw Error('PACKAGE_MATERIAL');verifyStagedPackageCheckpoint(journal,packageProof,marker.proof.source);verifyStagedProtocolObjectCheckpoint(journal,marker.proof);
  const logical=readProtocolObjectSource(marker.proof,marker.parts);if(logical.digest!==compiled.protocolDigest||!secureEqual(logical.package_source,packageProof)||!secureEqual(logical.manifest,compiled.manifest))throw Error('COMBINED_LOGICAL');
  const pending=Object.entries(agent.state.pending);if(pending.length!==1||pending[0][1].body.commit.payload.action_id!=='secure.structure.begin')throw Error('COMBINED_PENDING');
  extra={package_source:packageProof,object_source:marker.proof,source_parts:packageProof.parts.length,object_parts:marker.proof.parts.length,material_bytes:selected.material_bytes,logical_bytes:selected.logical_bytes,pending_command_id:pending[0][0],pending_commit_hash:await secureHash(pending[0][1].body.commit),pending_count:1,completed_sequence:null};
 }else if(mode==='implicit-later'||mode==='object-later'){
  const wiki=journal.objects.find(r=>r.kind==='instances'&&r.value.origin_entrypoint==='wiki');await agent.action(workspace,wiki.id,'wiki.create',{title:'Later implicit history',body:'Legal signed history after original END'});journal=await agent.journal(workspace);
  const record=journal.objects.find(r=>r.kind==='records'&&r.value.payload?.title==='Later implicit history');if(!record||journal.checkpoint.sequence!==completedSequence+1)throw Error('LATER_RECORD');
  extra={completed_sequence:completedSequence,completed_head:completedHead,later_record:record,...(mode==='implicit-later'?{composition:resolved.composition}:{object_source:agent.state.protocol_object_stage_intents?.[key]?.proof,source_parts:agent.state.protocol_object_stage_intents?.[key]?.parts.length}),pending_count:0};if(mode==='object-later'&&(!extra.object_source||extra.source_parts<2))throw Error('OBJECT_COMPLETED_PROOF');
 }else{
  const omitted={...options};delete omitted.dependencies;
  let failure;try{await resolveProtocolInstall(prior,omitted,agent.transport.discovery.protocol_features??[]);}catch(e){failure=e.code??e.message;}if(!failure)throw Error('ORIGINAL_PREFIX_RESOLVED_FUTURE');
  const dep=selected.dependencies[0];if(journal.objects.some(r=>r.kind==='protocols'&&r.id===dep.digest))throw Error('DEPENDENCY_ALREADY_INSTALLED');
  await agent.installProtocol(workspace,{instance_id:randomBytes(32).toString('base64url'),entrypoint:'later_dependency',manifest:dep.manifest,grants:[]});journal=await agent.journal(workspace);
  const now=await resolveProtocolInstall(journal,omitted,agent.transport.discovery.protocol_features??[]);if(now.intentHash!==resolved.intentHash||!journal.objects.some(r=>r.kind==='protocols'&&r.id===dep.digest))throw Error('LATER_DEPENDENCY_PROOF');
  writeFileSync(join(dir,'original-options.json'),JSON.stringify(options),{mode:0o600,flag:'wx'});options=omitted;extra={completed_sequence:completedSequence,completed_head:completedHead,original_predecessor_sequence:prior.checkpoint.sequence,original_prefix_resolution_failure:failure,latest_omitted_resolution_matches_original:true,dependency_installed_later:true,composition:resolved.composition,pending_count:0};
 }
 if(agent.state.protocol_install_intents?.[key]!==resolved.intentHash)throw Error('INTENT_LOST');writeFileSync(paths.options_path,JSON.stringify(options),{mode:0o600,flag:'wx'});
 console.log(JSON.stringify({mode,...paths,workspace_id:workspace,owner_actor_id:agent.identity.actorId,owner_key_id:agent.identity.keyId,instance_id:instance,entrypoint:options.entrypoint,intent_hash:resolved.intentHash,original_begin_command_id:originalBeginId??extra.pending_command_id,protocol_digest:compiled.protocolDigest,latest_sequence:journal.checkpoint.sequence,latest_head:journal.checkpoint.head,initial_sequence:prior.checkpoint.sequence,compiler_equality:true,original_intent_preserved:true,...extra}));
}finally{agent.close();}
