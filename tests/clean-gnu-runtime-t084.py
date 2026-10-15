#!/usr/bin/env python3
"""Three compiler-free runtime roots; offline installed local public API smoke."""
from pathlib import Path
import os,sys,json,hashlib,shutil,subprocess,re,time,datetime
MAIN=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012');COHORT=MAIN/'.build-artifacts/resource-sdk-t082-20261015';OLD=COHORT/'rootfs';SDK=OLD/'work/sdk-config-t062-20261015';BASE=MAIN/'.build-artifacts/clean-gnu-runtime-t084-20261015';HOME='/home/offline space 用户';PIN='a69929f1e1d44612b92be007df17ecb750529df5'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def guard():
 assert sha(COHORT/'artifact-manifest.sha256')=='4e924c841da539aa9325f630bd0f217eb55df5006a393333d331c4a2ce9285e9'
 for n,c in [('artifact-manifest.sha256',COHORT),('source-manifest-final.sha256',SDK)]:subprocess.run(['sha256sum','-c','--status',str(COHORT/n)],cwd=c,check=True)
def copy(src,dst):
 dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
def needed(p):
 if p.read_bytes()[:4]!=b'\x7fELF':return []
 s=subprocess.check_output(['readelf','-d',str(p)],text=True);return re.findall(r'Shared library: \[(.*?)\]',s)
def resolve_lib(name):
 for directory in [OLD/'usr/lib64',OLD/'usr/lib',OLD/'opt/_internal/cpython-3.11.17/lib',OLD/'opt/_internal/sqlite3/lib',OLD/'opt/_internal/mpdecimal-4/lib',OLD/'opt/_internal/zstd-1/lib']:
  p=directory/name
  if p.is_file():
   real=p.resolve();assert real.is_relative_to(OLD),str(real);return real
 raise AssertionError('missing exact runtime library '+name)
def closure(root,files):
 pending=list(files);seen=set();libs=[]
 while pending:
  p=pending.pop()
  for n in needed(p):
   if n in seen:continue
   seen.add(n);src=resolve_lib(n);dst=root/'lib64'/n;copy(src,dst);libs.append(dict(soname=n,source=str(src),path=str(dst.relative_to(root)),sha256=sha(dst)));pending.append(dst)
 loader=root/'lib64/ld-linux-x86-64.so.2'
 if not loader.exists():src=resolve_lib('ld-linux-x86-64.so.2');copy(src,loader);libs.append(dict(soname=loader.name,source=str(src),path=str(loader.relative_to(root)),sha256=sha(loader)))
 return libs
def public_modes(root):
 root.chmod(0o755)
 private=root/HOME.lstrip('/')
 for p in root.rglob('*'):
  if p.is_dir() and p!=private and not p.is_relative_to(private):p.chmod(0o1777 if p==root/'tmp' else 0o755)
 assert private.stat().st_mode&0o777==0o700
def construct(label):
 root=BASE/label;root.mkdir(exist_ok=True);(root/'tmp').mkdir(mode=0o1777,exist_ok=True);(root/'tmp').chmod(0o1777);home=root/HOME.lstrip('/');home.mkdir(parents=True,mode=0o700,exist_ok=True);os.chown(home,65534,65534);(root/'etc').mkdir(exist_ok=True)
 for n in ['passwd','group','nsswitch.conf']:copy(OLD/'etc'/n,root/'etc'/n)
 native=[]
 if label=='cli':copy(SDK/'target/release/peerwork',root/'usr/bin/peerwork');native=[root/'usr/bin/peerwork']
 elif label=='python':
  prefix=OLD/'opt/_internal/cpython-3.11.17';copy(prefix/'bin/python3.11',root/'usr/bin/python3');stdlib=root/'usr/lib/python3.11'
  exclude={'site-packages','__pycache__','test','tests','config-3.11-x86_64-linux-gnu','distutils','ensurepip','idlelib','turtledemo'}
  shutil.copytree(prefix/'lib/python3.11',stdlib,dirs_exist_ok=True,ignore=shutil.ignore_patterns(*exclude,'*.h','*.hpp','*.a'))
  for name in ['pip','pip-26.2.1.dist-info']:shutil.copytree(prefix/'lib/python3.11/site-packages'/name,stdlib/'site-packages'/name,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.h','*.hpp','*.a'))
  copy(SDK/'dist/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl',root/'packages/sdk.whl')
  # Preserve exact wheel filename required by pip; no renaming of tags.
  (root/'packages/sdk.whl').rename(root/'packages/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl')
  native=[root/'usr/bin/python3']+[p for p in stdlib.rglob('*.so')]+[SDK/'dist/python-consumer/peerwork/_peerwork_native.abi3.so']
 else:
  copy(OLD/'opt/node24/bin/node',root/'usr/bin/node');npm=root/'usr/lib/npm';oldnpm=OLD/'opt/node24/lib/node_modules/npm'
  def npm_ignore(directory,names):
   out=set(shutil.ignore_patterns('node-gyp-bin','__pycache__','*.h','*.hpp','*.a')(directory,names))
   if Path(directory)==oldnpm/'node_modules':out.add('node-gyp')
   return out
  shutil.copytree(oldnpm,npm,dirs_exist_ok=True,ignore=npm_ignore)
  for n in ['peerwork-agent-sdk-0.0.1.tgz','peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz']:copy(SDK/'dist/npm'/n,root/'packages'/n)
  native=[root/'usr/bin/node',SDK/'target/release/libpeerwork_node_native.so']
 libs=closure(root,native);public_modes(root);files=[p for p in root.rglob('*')if p.is_file()];forbidden={'rustc','rustdoc','cargo','cc','gcc','g++','c++','clang','clang++','ld','ld.lld','lld','as','make','cmake','ninja','pkg-config','docker','dockerd','postgres','mysqld','node-gyp','node-gyp.js'}
 assert not[(str(p),p.name)for p in files if p.name in forbidden or p.suffix in {'.h','.hpp','.a'}]
 assert not(root/'usr/include').exists()and not(root/'usr/lib/python3.11/config-3.11-x86_64-linux-gnu').exists()
 if label!='python':assert not any(p.name.startswith(('python','libpython')) for p in files)
 if label!='node':assert not any(p.name in {'node','npm','npm-cli.js'} for p in files)
 if label!='cli':assert not any(p.name=='peerwork' and p.stat().st_mode&0o111 for p in files)
 for p in native:
  for n in needed(p):assert(root/'lib64'/n).is_file()
 # Full physical namespace inventory, beyond PATH-only hiding.
 rows=[dict(path=str(p.relative_to(root)),size=p.stat().st_size,sha256=sha(p))for p in files];dump(BASE/(label+'-preflight.json'),dict(result='PASS',label=label,source=PIN,files=len(rows),bytes=sum(x['size']for x in rows),required_libraries=libs,inventory=rows,absent_buildtools_headers_other_runtimes=True))
 return root,home
def execute(label,root,home):
 calls=[]
 def run(name,args,code=0,env=None):
  argv=['/usr/sbin/chroot','--userspec=65534:65534',str(root),*args];start=datetime.datetime.now(datetime.timezone.utc);t=time.monotonic();r=subprocess.run(argv,env=dict(HOME=HOME,PATH='/usr/bin',PYTHONHOME='/usr',PYTHONDONTWRITEBYTECODE='1',PIP_DISABLE_PIP_VERSION_CHECK='1'),capture_output=True,text=True,timeout=120)
  v=dict(label=name,argv=argv,exit_code=r.returncode,seconds=time.monotonic()-t,start_utc=start.isoformat(),stdout=r.stdout,stderr=r.stderr);calls.append(v);dump(BASE/(label+'-calls.json'),calls);assert r.returncode==code,(label,name,r.stderr);return r
 state=home/'profile';state.mkdir(mode=0o700,exist_ok=True);assert not(state/'identity.state').exists(),'do not repeat SDK case';os.chown(state,65534,65534);cf=home/'config.json';dump(cf,dict(origin='https://control.invalid',state_dir=HOME+'/profile'));cf.chmod(0o600);os.chown(cf,65534,65534)
 if label=='python':
  body='''import os,sys,json,hashlib
from pathlib import Path
import peerwork,peerwork._peerwork_native as native
assert os.geteuid()==65534
home=Path(os.environ['HOME']);identity=str(home/'profile/identity.state');a=peerwork.create_identity(identity);assert peerwork.open_identity(identity)==a
o=peerwork.SecureOwnerWorkspaceClient('https://control.invalid',str(home/'profile'));assert o.operations()==[] and peerwork.SecureOwnerWorkspaceClient('https://control.invalid',str(home/'profile')).operations()==[]
assert peerwork.__file__==str(home/'installed/peerwork/__init__.py')
print(json.dumps(dict(result='PASS',uid=os.geteuid(),runtime=sys.version,identity_public=a,operations=[],paths=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in [Path(peerwork.__file__),Path(native.__file__)]])))
'''
  p=home/'consumer.py';p.write_text(body);os.chown(p,65534,65534)
  run('offline pip no compiler',['/usr/bin/python3','-m','pip','install','--no-index','--no-deps','--target',HOME+'/installed','/packages/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl'])
  # Insert only fresh user install; no fallback to build root packages.
  result=json.loads(run('installed public identity/open/operations',['/usr/bin/python3','-c',"import sys,runpy;sys.path.insert(0,"+repr(HOME+'/installed')+");runpy.run_path("+repr(HOME+'/consumer.py')+",run_name='__main__')"]).stdout)
 elif label=='node':
  package=home/'package.json';package.write_text('{"name":"clean-offline-t084","private":true}');os.chown(package,65534,65534)
  run('offline npm ignore-scripts no compiler',['/usr/bin/node','/usr/lib/npm/bin/npm-cli.js','install','--prefix',HOME,'--cache',HOME+'/npm-cache','--offline','--ignore-scripts','--no-audit','--no-fund','--no-save','/packages/peerwork-agent-sdk-0.0.1.tgz','/packages/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz'])
  body='''const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');const home=process.env.HOME,s=require(home+'/node_modules/@peerwork/agent-sdk');(async()=>{if(process.geteuid()!==65534)throw Error('UID');const p=home+'/profile/identity.state',a=await s.createIdentity(p);if(JSON.stringify(a)!==JSON.stringify(await s.openIdentity(p)))throw Error('identity');for(let i=0;i<2;i++)if((await s.openSecureOwnerWorkspaces({origin:'https://control.invalid',stateDir:home+'/profile'}).operations()).length)throw Error('history');const paths=[require.resolve(home+'/node_modules/@peerwork/agent-sdk'),Object.keys(require.cache).find(p=>p.endsWith('.node'))];console.log(JSON.stringify({result:'PASS',uid:process.geteuid(),runtime:process.version,identity_public:a,operations:[],paths:paths.map(p=>({path:p,sha256:crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}))}));})().catch(e=>{console.error(e.code||e.message);process.exitCode=1})'''
  p=home/'consumer.cjs';p.write_text(body);os.chown(p,65534,65534);result=json.loads(run('installed public identity/open/operations',['/usr/bin/node',HOME+'/consumer.cjs']).stdout)
 else:
  public=json.loads(run('CLI explicit public identity create',['/usr/bin/peerwork','identity','create',HOME+'/profile/identity.state']).stdout)
  assert json.loads(run('CLI public identity reopen',['/usr/bin/peerwork','identity','info',HOME+'/profile/identity.state']).stdout)==public
  for i in range(2):assert json.loads(run('CLI fresh local Owner operations',['/usr/bin/peerwork','secure','owner-operations',HOME+'/config.json']).stdout)==[]
  result=dict(result='PASS',identity_public=public,operations=[],paths=[dict(path='/usr/bin/peerwork',sha256=sha(root/'usr/bin/peerwork'))],runtime='native GNU x64 CLI',uid=65534)
 result.update(source=PIN,interface=label,glibc_loader=run('actual runtime loader',['/lib64/ld-linux-x86-64.so.2','--version']).stdout.splitlines()[0]);dump(BASE/(label+'-result.json'),result)
 return result

def main():
 os.umask(0o077);BASE.mkdir(exist_ok=True);assert not list(BASE.glob('*-calls.json')),'consumer already ran; no unchanged retry';guard();start=datetime.datetime.now(datetime.timezone.utc);t=time.monotonic();roots=[]
 for label in ['cli','python','node']:
  roots.append((label,BASE/label,BASE/label/HOME.lstrip('/'))) if '--resume-ready' in sys.argv else roots.append((label,*construct(label)))
 dump(BASE/'ready.json',dict(result='PASS',source=PIN,construct_seconds=time.monotonic()-t,start_utc=start.isoformat(),end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),all_absence_preflights_pass=True))
 probes=[]
 for label,root,home in ([] if '--resume-ready' in sys.argv else roots):
  commands=[['/lib64/ld-linux-x86-64.so.2','--version']]
  if label=='cli':commands.append(['/usr/bin/peerwork','--help'])
  if label=='python':commands.append(['/usr/bin/python3','-m','pip','--version'])
  if label=='node':commands.append(['/usr/bin/node','/usr/lib/npm/bin/npm-cli.js','--version'])
  for command in commands:
   a=['/usr/sbin/chroot','--userspec=65534:65534',str(root),*command];r=subprocess.run(a,env=dict(HOME=HOME,PATH='/usr/bin',PYTHONHOME='/usr',PYTHONDONTWRITEBYTECODE='1'),text=True,capture_output=True);probes.append(dict(interface=label,argv=a,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));dump(BASE/'startup-preflight.json',probes);assert r.returncode==0,(label,r.stderr)
 result=[]
 for label,root,home in roots:
  result.append(execute(label,root,home));guard()
  # Recheck whole runtime inventory after installers; packages cannot introduce compilers/other-language runtimes.
  files=[p for p in root.rglob('*')if p.is_file()];forbidden={'rustc','cargo','gcc','cc','clang','clang++','g++','ld','ld.lld','lld','as','make','cmake','ninja','docker','dockerd','postgres','mysqld','node-gyp','node-gyp.js'}
  assert not[p for p in files if p.name in forbidden or p.suffix in {'.h','.hpp','.a'}]
  if label!='python':assert not[p for p in files if p.name.startswith(('python','libpython'))]
  if label!='node':assert not[p for p in files if p.name in {'node','npm-cli.js'}]
  if label!='cli':assert not[p for p in files if p.name=='peerwork' and p.stat().st_mode&0o111]
 dump(BASE/'summary.json',dict(result='PASS',source=PIN,interfaces=result,no_http=True,no_compiler_or_other_runtime=True,guards='source797/artifact14 before and after each',finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
if __name__=='__main__':main()
