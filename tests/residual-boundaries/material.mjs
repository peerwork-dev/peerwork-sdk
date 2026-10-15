import{createLegacyComposedInstallMaterial}from'../legacy-owner-install-composition-material.mjs';
import{pathToFileURL}from'node:url';
export async function combinedMaterial(reference){
 const load=n=>import(pathToFileURL(reference+'/dist-workspace/src/'+n+'.js').href);
 const base=await createLegacyComposedInstallMaterial(reference,true);
 const {exactPackageLoader,createProtocolPackageClosure}=await load('protocol-package-closure');
 const {parseProtocolPackage}=await load('protocol-package');const {previewProtocolPackage}=await load('protocol-compiler');const {compilePackageMaterial}=await load('workspace-protocol-package-source');
 const loader=exactPackageLoader(base.material.closure),root=loader(base.material.closure.root_package_digest),bundle=structuredClone(root.bundle);
 bundle.files['README.md']+='\n'+'P'.repeat(70000);
 const preview=previewProtocolPackage(bundle,{loadExactPackage:loader});if(!preview.passed)throw Error('COMBINED_AUTHOR_PREVIEW');
 bundle.files['release.lock.json']=JSON.stringify({...JSON.parse(bundle.files['release.lock.json']),output_protocol_digest:preview.protocolDigest});
 const dependencies=Object.keys(base.material.closure.packages).filter(d=>d!==root.packageDigest).map(loader);
 const material={v:1,closure:createProtocolPackageClosure(parseProtocolPackage(bundle),dependencies),bindings:{}};
 const compiled=compilePackageMaterial(material);
 const logicalBytes=Buffer.byteLength(JSON.stringify({manifest:compiled.manifest,resolved_manifest:compiled.manifest}));
 if(Buffer.byteLength(JSON.stringify(material))<=65536||logicalBytes<=65536||compiled.protocolDigest!==base.protocolDigest)throw Error('COMBINED_SIZE_COMPILER_PRECONDITION');
 return{material,compiled,material_bytes:Buffer.byteLength(JSON.stringify(material)),logical_bytes:logicalBytes,readme_bytes:Buffer.byteLength(bundle.files['README.md'])};
}
