#!/usr/bin/env python3
"""Offline installed de384 transport option smoke; fresh unprivileged consumers."""
from pathlib import Path
import os,sys,json,subprocess,hashlib,shutil,time,datetime
GUEST='/work/sdk-config-t062-20261015';HOME='/work/t089 public consumers 用户';PIN='de384e52782f4e3f9fb6fe0b6a02cd3abe80f73d'
def child():
 assert os.geteuid()==65534;os.umask(0o077);home=Path(HOME);os.chdir(home);calls=[]
 def run(label,argv,code=0):
  t=time.monotonic();r=subprocess.run(argv,text=True,capture_output=True);calls.append(dict(label=label,argv=argv,exit_code=r.returncode,seconds=time.monotonic()-t,stdout=r.stdout,stderr=r.stderr));(home/'calls.json').write_text(json.dumps(calls,indent=2)+'\n');assert r.returncode==code,(label,r.stderr);return r
 wheel=GUEST+'/dist/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl';pyhome=home/'python';np=home/'node'
 run('fresh offline user pip',['/opt/python/cp311-cp311/bin/python','-m','pip','install','--no-index','--no-deps','--target',str(pyhome),wheel])
 np.mkdir();(np/'package.json').write_text('{"name":"offline-t082","private":true}')
 run('fresh offline user npm ignores scripts',['/opt/node24/bin/npm','install','--prefix',str(np),'--cache',str(home/'npm-cache'),'--offline','--ignore-scripts','--no-audit','--no-fund','--no-save',GUEST+'/dist/npm/peerwork-agent-sdk-0.0.1.tgz',GUEST+'/dist/npm/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz'])
 binary=home/'bin';binary.mkdir();cli=binary/'peerwork';shutil.copy2(GUEST+'/target/release/peerwork',cli)
 sys.path.insert(0,str(pyhome));import peerwork,peerwork._peerwork_native as native
 assert peerwork.__file__==str(pyhome/'peerwork/__init__.py') and native.__file__==str(pyhome/'peerwork/_peerwork_native.abi3.so')
 state=home/'profile';state.mkdir(mode=0o700);public=peerwork.create_identity(str(state/'identity.state'))
 owner=peerwork.SecureOwnerWorkspaceClient('https://control.invalid',str(state));assert 'transport'not in owner._config and owner.operations()==[]
 assert peerwork.TransportOptions()._json_value()==dict(request_timeout_ms=15000,additional_root_pem_files=[])
 selected=peerwork.TransportOptions(request_timeout_ms=321,additional_root_pem_files=('public-ca.pem',));explicit_owner=peerwork.SecureOwnerWorkspaceClient('https://control.invalid',str(state),transport=selected);assert explicit_owner._config['transport']==selected._json_value()and explicit_owner.operations()==[]
 tc=home/'transport-config.json';tc.write_text(json.dumps(dict(origin='https://control.invalid',state_dir=str(state),transport=selected._json_value())));tc.chmod(0o600)
 loaded=peerwork.load_config(str(tc));assert loaded['transport']==peerwork.TransportOptions(321,(str(home/'public-ca.pem'),))and not(home/'public-ca.pem').exists();assert peerwork.SecureOwnerWorkspaceClient(**loaded).operations()==[]
 roster=sorted(p.name for p in state.iterdir());errors=[]
 for invalid in [dict(request_timeout_ms=321),0,[]]:
  try:peerwork.SecureOwnerWorkspaceClient('https://control.invalid',str(state),transport=invalid);raise AssertionError('accepted invalid shape')
  except TypeError as e:errors.append({'type':type(e).__name__})
 for kwargs in [dict(request_timeout_ms=0),dict(request_timeout_ms=2**64),dict(additional_root_pem_files=('',))]:
  try:peerwork.TransportOptions(**kwargs);raise AssertionError('accepted invalid options')
  except ValueError as e:errors.append({'type':type(e).__name__})
 assert sorted(p.name for p in state.iterdir())==roster
 abi_options=peerwork.TransportOptions(321,());ffi_python=[]
 for transport in [None,abi_options]:
  kernel=peerwork.KernelClient('not-an-origin',str(state/'abi-kernel.sqlite'),str(state/'identity.state'),transport=transport)
  try:kernel.open();raise AssertionError('invalid origin accepted')
  except RuntimeError as e:assert 'invalid or unsupported server origin' in str(e);ffi_python.append(dict(client='kernel',transport='default'if transport is None else'321ms_emptyCA',native_message=str(e),exception=type(e).__name__))
  enrollment=peerwork.SecureRecipientEnrollmentClient('https://control.invalid',str(state),transport=transport)
  try:enrollment.pending();raise AssertionError('missing recipient accepted')
  except peerwork.RecipientEnrollmentError as e:assert e.code=='LOCAL_STATE_FAILED';ffi_python.append(dict(client='enrollment',transport='default'if transport is None else'321ms_emptyCA',native_code=e.code,native_message=str(e)))
  directory=peerwork.SecureIdentityDirectoryClient('https://control.invalid',str(state),transport=transport)
  try:directory.lookup('bad','bad');raise AssertionError('invalid peer accepted')
  except peerwork.IdentityDirectoryError as e:assert e.code=='DIRECTORY_INVALID';ffi_python.append(dict(client='directory',transport='default'if transport is None else'321ms_emptyCA',native_code=e.code,native_message=str(e)))
 abi_local_roster=sorted(q.name for q in state.iterdir())
 pkg=str(np/'node_modules/@peerwork/agent-sdk');node='/opt/node24/bin/node'
 js="const s=require(process.argv[1]);(async()=>{const state=process.argv[2],file=process.argv[3],o=s.openSecureOwnerWorkspaces({origin:'https://control.invalid',stateDir:state});if((await o.operations()).length)throw Error('history');const selected={requestTimeoutMs:321,additionalRootPemFiles:['public-ca.pem']};if((await s.openSecureOwnerWorkspaces({origin:'https://control.invalid',stateDir:state,transport:selected}).operations()).length)throw Error('history');const config=await s.loadConfig(file);if(config.transport.requestTimeoutMs!==321||config.transport.additionalRootPemFiles[0]!==process.env.HOME+'/public-ca.pem')throw Error('mapping');if((await s.openSecureOwnerWorkspaces(config).operations()).length)throw Error('loadedhistory');const errors=[];for(const transport of[null,[],{unknown:1},{requestTimeoutMs:0},{requestTimeoutMs:Number.MAX_SAFE_INTEGER+1},{additionalRootPemFiles:['']}]){try{s.openSecureOwnerWorkspaces({origin:'https://control.invalid',stateDir:state,transport});throw Error('accepted')}catch(e){if(!(e instanceof TypeError))throw e;errors.push({type:e.name});}}const ffi=[];for(const transport of[undefined,{requestTimeoutMs:321,additionalRootPemFiles:[]}]){for(const [client,invoke,code]of[['kernel',()=>s.openKernel({origin:'not-an-origin',journalPath:state+'/abi-kernel.sqlite',identityPath:state+'/identity.state',transport}),null],['enrollment',()=>s.openSecureRecipientEnrollment({origin:'https://control.invalid',stateDir:state,transport}).pending(),'LOCAL_STATE_FAILED'],['directory',()=>s.openSecureIdentityDirectory({origin:'https://control.invalid',stateDir:state,transport}).lookup('bad','bad'),'DIRECTORY_INVALID']]){try{await invoke();throw Error('unexpected success')}catch(e){if(e instanceof TypeError)throw e;if(code?e.code!==code:!e.message.includes('invalid or unsupported server origin'))throw e;ffi.push({client,transport:transport===undefined?'default':'321ms_emptyCA',nativeCode:e.code??null,nativeMessage:e.message});}}}console.log(JSON.stringify({ffi,errors,selected,loadedConfig:config,identity:await s.openIdentity(state+'/identity.state'),wrapper:require.resolve(process.argv[1]),native:Object.keys(require.cache).find(p=>p.endsWith('.node')),version:s.version(),runtime:process.version}));})().catch(e=>{console.error(e.code||e.message);process.exitCode=1})"
 n=json.loads(run('Node installed default explicit/helper/invalid transport',[node,'-e',js,pkg,str(state),str(tc)]).stdout);assert n['identity']==public and n['native']==str(np/'node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node')
 cf=home/'owner-config.json';cf.write_text(json.dumps(dict(origin='https://control.invalid',state_dir=str(state),transport=selected._json_value())))
 assert json.loads(run('CLI same protected profile local operations',[str(cli),'secure','owner-operations',str(cf)]).stdout)==[]
 assert json.loads(run('CLI public identity reopen',[str(cli),'identity','info',str(state/'identity.state')]).stdout)==public
 help=json.loads(run('CLI Owner help transport field',[str(cli),'secure','owner-create','--help']).stdout);assert any('transport' in x for x in help['config_fields'])
 resolved=json.loads(run('CLI resolver transport helper',[str(cli),'config','resolve',str(tc)]).stdout);assert resolved['transport']==dict(request_timeout_ms=321,additional_root_pem_files=[str(home/'public-ca.pem')])
 for number in ['0','18446744073709551616']:
  r=run('CLI invalid deadline flag '+number,[str(cli),'secure','read','--request-timeout-ms='+number],1);e=json.loads(r.stderr);assert e['code']=='CONFIG_INVALID' and not r.stdout
 assert peerwork.open_identity(str(state/'identity.state'))==public
 paths=[Path(peerwork.__file__),Path(native.__file__),Path(n['wrapper']),Path(n['native']),cli]
 result=dict(result='PASS',source=PIN,uid=os.getuid(),euid=os.geteuid(),no_http=True,default_transport=peerwork.TransportOptions()._json_value(),explicit_transport=selected._json_value(),python_invalid=errors,python_compiled_ffi=ffi_python,abi_local_roster=abi_local_roster,node=n,identity_public=public,python_runtime=sys.version,version=peerwork.version(),files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),size=p.stat().st_size)for p in paths],calls=calls)
 (home/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
def catalog_child():
 assert os.geteuid()==65534;sys.path.insert(0,str(Path(HOME)/'python'));import peerwork
 rows=[]
 for options in [None,peerwork.TransportOptions(321,())]:
  try:peerwork.PublicCatalogClient('not-an-origin',transport=options).search('sdk');raise AssertionError('origin accepted')
  except peerwork.PublicCatalogError as e:assert e.code=='CATALOG_INPUT_INVALID';rows.append(dict(transport='default'if options is None else'321ms_emptyCA',code=e.code,message=str(e)))
 js="const s=require(process.argv[1]);(async()=>{const rows=[];for(const transport of[undefined,{requestTimeoutMs:321,additionalRootPemFiles:[]}]){try{await s.openPublicCatalog({origin:'not-an-origin',transport}).search('sdk');throw Error('accepted')}catch(e){if(e instanceof TypeError||e.code!=='CATALOG_INPUT_INVALID')throw e;rows.push({transport:transport===undefined?'default':'321ms_emptyCA',code:e.code,message:e.message});}}console.log(JSON.stringify(rows));})().catch(e=>{console.error(e.message);process.exitCode=1})"
 r=subprocess.run(['/opt/node24/bin/node','-e',js,HOME+'/node/node_modules/@peerwork/agent-sdk'],text=True,capture_output=True);assert r.returncode==0,r.stderr
 print(json.dumps(dict(result='PASS',source=PIN,uid=os.geteuid(),python=rows,node=json.loads(r.stdout),no_http=True,scope='compiled catalog configuration/default/explicit JSON; invalid origin before request')))
def host(base):
 b=Path(base).resolve();root=b/'rootfs';home=root/HOME.lstrip('/');home.mkdir(mode=0o700);os.chown(home,65534,65534);shutil.copy2(__file__,home/'smoke.py');os.chown(home/'smoke.py',65534,65534)
 argv=['/usr/sbin/chroot','--userspec=65534:65534',str(root),'/usr/bin/env','-i','HOME='+HOME,'PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1','PIP_DISABLE_PIP_VERSION_CHECK=1','/opt/python/cp311-cp311/bin/python','-I',HOME+'/smoke.py','--child'];(b/'smoke-invocation.json').write_text(json.dumps(argv,indent=2)+'\n');start=datetime.datetime.now(datetime.timezone.utc);t=time.monotonic()
 with(b/'smoke.stdout').open('w')as out,(b/'smoke.stderr').open('w')as err:r=subprocess.run(argv,stdout=out,stderr=err)
 (b/'smoke.terminal.json').write_text(json.dumps(dict(start_utc=start.isoformat(),end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-t,exit_code=r.returncode,argv=argv),indent=2)+'\n');raise SystemExit(r.returncode)
if __name__=='__main__':catalog_child()if'--catalog-child'in sys.argv else child()if'--child'in sys.argv else host(sys.argv[1])
