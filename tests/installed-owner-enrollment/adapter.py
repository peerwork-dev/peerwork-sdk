"""Invoke one installed public interface; stdout/stderr preserve its error envelope."""
import json,subprocess,sys
from pathlib import Path
interface,sdk_arg,verb,config_arg,*args=sys.argv[1:];sdk=Path(sdk_arg);config_file=Path(config_arg);config=json.loads(config_file.read_text())
if interface=='cli':
 argv=[str(sdk/'target/release/peerwork')]
 argv+=['identity','import-legacy-owner-pem',config_arg,*args] if verb=='identity-import' else ['secure',verb,config_arg,*args]
 raise SystemExit(subprocess.run(argv).returncode)
if interface=='python':
 installed=sdk/'dist/python-consumer';sys.path.insert(0,str(installed));import peerwork
 assert Path(peerwork.__file__).resolve()==(installed/'peerwork/__init__.py').resolve()
 try:
  if verb=='identity-import':value=peerwork.import_legacy_owner_identity(config_arg,args[0])
  else:
   owner=peerwork.SecureOwnerWorkspaceClient(config['origin'],config['state_dir'],allow_loopback_http=config['allow_loopback_http'])
   if verb=='owner-create':
    request=json.loads(Path(args[0]).read_text());value=owner.create(request['name'],request['visibility'],structured=request['structured'])
   elif verb=='owner-resume':value=owner.resume(args[0])
   elif verb=='owner-operations':value=owner.operations()
   elif verb=='owner-read':value=owner.read(args[0])
   else:raise AssertionError('unknown public operation')
 except peerwork.OwnerWorkspaceError as error:
  print(json.dumps(dict(code=error.code,message=str(error))),file=sys.stderr);raise SystemExit(1)
 print(json.dumps(value));raise SystemExit(0)
assert interface=='node'
# sdk is rootfs/work/<sdk>; executable is rootfs/opt/node24/bin/node.
node=sdk.parent.parent/'opt/node24/bin/node'
program=r'''
const fs=require('node:fs'),x=JSON.parse(fs.readFileSync(0,'utf8')),sdk=require(x.package);
void(async()=>{
 let value;
 if(x.verb==='identity-import')value=await sdk.importLegacyOwnerIdentity(x.configFile,x.args[0]);
 else{
  const owner=sdk.openSecureOwnerWorkspaces({origin:x.config.origin,stateDir:x.config.state_dir,allowLoopbackHttp:x.config.allow_loopback_http});
  switch(x.verb){
   case 'owner-create':value=await owner.create(JSON.parse(fs.readFileSync(x.args[0],'utf8')));break;
   case 'owner-resume':value=await owner.resume(x.args[0]);break;
   case 'owner-operations':value=await owner.operations();break;
   case 'owner-read':value=await owner.read(x.args[0]);break;
   default:throw new Error('unknown public operation');
  }
 }
 console.log(JSON.stringify(value));
})().catch(error=>{console.error(JSON.stringify({code:error.code,message:error.message}));process.exitCode=1;});
'''
raise SystemExit(subprocess.run([str(node),'-e',program],input=json.dumps(dict(package=str(sdk/'dist/node-consumer/node_modules/@peerwork/agent-sdk'),verb=verb,config=config,configFile=config_arg,args=args)),text=True).returncode)
