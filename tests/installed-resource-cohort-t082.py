#!/usr/bin/env python3
"""Offline installed a699 resource option smoke; fresh unprivileged consumers."""
from pathlib import Path
import os,sys,json,subprocess,hashlib,shutil,time,datetime
GUEST='/work/sdk-config-t062-20261015';HOME='/work/t082 public consumers 用户';PIN='a69929f1e1d44612b92be007df17ecb750529df5'
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
 owner=peerwork.SecureOwnerWorkspaceClient('https://control.invalid',str(state));assert owner._config['max_replay_commits']==102400 and owner.operations()==[]
 assert peerwork.SecureOwnerWorkspaceClient('https://control.invalid',str(state),max_replay_commits=27).operations()==[]
 roster=sorted(p.name for p in state.iterdir());errors=[]
 for n in [0,2**64]:
  try:peerwork.SecureOwnerWorkspaceClient('https://control.invalid',str(state),max_replay_commits=n);raise AssertionError('accepted invalid count')
  except ValueError as e:errors.append({'value':str(n),'type':type(e).__name__})
 assert sorted(p.name for p in state.iterdir())==roster
 pkg=str(np/'node_modules/@peerwork/agent-sdk');node='/opt/node24/bin/node'
 js='''const s=require(process.argv[1]);(async()=>{const state=process.argv[2],o=s.openSecureOwnerWorkspaces({origin:'https://control.invalid',stateDir:state});if((await o.operations()).length)throw Error('history');const errors=[];for(const n of[0,Number.MAX_SAFE_INTEGER+1]){try{s.openSecureOwnerWorkspaces({origin:'https://control.invalid',stateDir:state,maxReplayCommits:n});throw Error('accepted')}catch(e){if(!(e instanceof TypeError))throw e;errors.push({value:String(n),type:e.name});}}console.log(JSON.stringify({errors,identity:await s.openIdentity(state+'/identity.state'),wrapper:require.resolve(process.argv[1]),native:Object.keys(require.cache).find(p=>p.endsWith('.node')),version:s.version(),runtime:process.version}));})().catch(e=>{console.error(e.code||e.message);process.exitCode=1})'''
 n=json.loads(run('Node installed default and invalid counts',[node,'-e',js,pkg,str(state)]).stdout);assert n['identity']==public and n['native']==str(np/'node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node')
 cf=home/'owner-config.json';cf.write_text(json.dumps(dict(origin='https://control.invalid',state_dir=str(state),max_replay_commits=102400)))
 assert json.loads(run('CLI same protected profile local operations',[str(cli),'secure','owner-operations',str(cf)]).stdout)==[]
 assert json.loads(run('CLI public identity reopen',[str(cli),'identity','info',str(state/'identity.state')]).stdout)==public
 help=json.loads(run('CLI Owner help count field',[str(cli),'secure','owner-create','--help']).stdout);assert any('max_replay_commits' in x for x in help['config_fields'])
 for number in ['0','18446744073709551616']:
  r=run('CLI invalid count flag '+number,[str(cli),'secure','read','--max-replay-commits='+number],1);e=json.loads(r.stderr);assert e['code']=='USAGE' and not r.stdout
 assert peerwork.open_identity(str(state/'identity.state'))==public
 paths=[Path(peerwork.__file__),Path(native.__file__),Path(n['wrapper']),Path(n['native']),cli]
 result=dict(result='PASS',source=PIN,uid=os.getuid(),euid=os.geteuid(),no_http=True,default_count=102400,explicit_count=27,python_invalid=errors,node=n,identity_public=public,python_runtime=sys.version,version=peerwork.version(),files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),size=p.stat().st_size)for p in paths],calls=calls)
 (home/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
def host(base):
 b=Path(base).resolve();root=b/'rootfs';home=root/HOME.lstrip('/');home.mkdir(mode=0o700);os.chown(home,65534,65534);shutil.copy2(__file__,home/'smoke.py');os.chown(home/'smoke.py',65534,65534)
 argv=['chroot','--userspec=65534:65534',str(root),'/usr/bin/env','-i','HOME='+HOME,'PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1','PIP_DISABLE_PIP_VERSION_CHECK=1','/opt/python/cp311-cp311/bin/python','-I',HOME+'/smoke.py','--child'];(b/'smoke-invocation.json').write_text(json.dumps(argv,indent=2)+'\n');start=datetime.datetime.now(datetime.timezone.utc);t=time.monotonic()
 with(b/'smoke.stdout').open('w')as out,(b/'smoke.stderr').open('w')as err:r=subprocess.run(argv,stdout=out,stderr=err)
 (b/'smoke.terminal.json').write_text(json.dumps(dict(start_utc=start.isoformat(),end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-t,exit_code=r.returncode,argv=argv),indent=2)+'\n');raise SystemExit(r.returncode)
if __name__=='__main__':child()if'--child'in sys.argv else host(sys.argv[1])
