#!/usr/bin/env python3
"""Small installed-package discovery/Owner consumption smoke; no HTTP or identity reads."""
from pathlib import Path
import os,sys,json,subprocess,hashlib,shutil,datetime,time
GUEST='/work/sdk-config-t062-20261015';HOME='/work/t062 protected home 用户'
def child():
    assert os.geteuid()==65534
    os.umask(0o077);home=Path(HOME);os.chdir(home);sys.path.insert(0,GUEST+'/dist/python-consumer');import peerwork,peerwork._peerwork_native as native
    assert peerwork.__file__==GUEST+'/dist/python-consumer/peerwork/__init__.py'
    assert native.__file__==GUEST+'/dist/python-consumer/peerwork/_peerwork_native.abi3.so'
    assert callable(peerwork.load_config)
    parent=home/'.config/peerwork';parent.mkdir(parents=True,mode=0o700);profile=parent/'profile 用户';profile.mkdir(mode=0o700)
    identity=profile/'identity.state';public=peerwork.create_identity(str(identity));meta=lambda:(identity.stat().st_ino,identity.stat().st_size,identity.stat().st_mtime_ns);before_identity=meta()
    config=parent/'config.json';config.write_text(json.dumps({'origin':'https://control.invalid','state_dir':'profile 用户'}));config.chmod(0o400)
    explicit=home/'explicit.json';explicit.write_text(json.dumps({'origin':'https://control.invalid','state_dir':str(profile)}));explicit.chmod(0o400)
    before=(config.read_bytes(),config.stat().st_mtime_ns,explicit.read_bytes(),explicit.stat().st_mtime_ns);parent.chmod(0o500)
    expected={'origin':'https://control.invalid','state_dir':str(profile)};assert peerwork.load_config()==expected and peerwork.load_config(str(explicit))==expected
    assert peerwork.SecureOwnerWorkspaceClient(**peerwork.load_config()).operations()==[]
    calls=[];node='/opt/node24/bin/node';pkg=GUEST+'/dist/node-consumer/node_modules/@peerwork/agent-sdk';cli=GUEST+'/target/release/peerwork'
    def call(label,argv,env=None,code=0):
        r=subprocess.run(argv,env=env,text=True,capture_output=True);calls.append(dict(label=label,argv=argv,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));assert r.returncode==code,(label,r.stderr);return r
    js='const s=require(process.argv[1]);(async()=>{const a=await s.loadConfig();const b=await s.loadConfig(process.argv[2]);if(JSON.stringify(a)!==JSON.stringify(b))throw Error("config mismatch");if((await s.openSecureOwnerWorkspaces(a).operations()).length)throw Error("history");const id=await s.openIdentity(process.argv[3]);console.log(JSON.stringify({config:a,identity:id,wrapper:require.resolve(process.argv[1]),native:Object.keys(require.cache).find(p=>p.endsWith(".node")),version:s.version(),runtime:process.version}));})().catch(e=>{console.error(e.code||e.message);process.exitCode=1})'
    n=json.loads(call('Node installed defaults/explicit/Owner',[node,'-e',js,pkg,str(explicit),str(identity)]).stdout);assert n['config']=={'origin':expected['origin'],'stateDir':expected['state_dir']} and n['identity']==public
    assert n['native']==GUEST+'/dist/node-consumer/node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node'
    a=json.loads(call('CLI installed default',[cli,'config','resolve']).stdout);b=json.loads(call('CLI installed explicit',[cli,'config','resolve',str(explicit)]).stdout);assert a==b==expected
    resolved=home/'resolved-owner.json';resolved.write_text(json.dumps(a));assert json.loads(call('CLI consumed resolver config',[cli,'secure','owner-operations',str(resolved)]).stdout)==[]
    assert json.loads(call('CLI public identity reopen',[cli,'identity','info',str(identity)]).stdout)==public
    failed=dict(os.environ,PEERWORK_CONFIG=str(home/'missing.json'))
    old=os.environ.get('PEERWORK_CONFIG');os.environ['PEERWORK_CONFIG']=failed['PEERWORK_CONFIG']
    try:
        try:peerwork.load_config();raise AssertionError('accepted')
        except peerwork.ConfigError as e:assert e.code=='CONFIG_MISSING';pyerror={'code':e.code,'message':str(e)}
    finally:
        if old is None:os.environ.pop('PEERWORK_CONFIG')
        else:os.environ['PEERWORK_CONFIG']=old
    errorjs='const s=require(process.argv[1]);s.loadConfig().then(()=>process.exitCode=3).catch(e=>{console.log(JSON.stringify({code:e.code,message:e.message}));})'
    ne=json.loads(call('Node safe missing/no fallback',[node,'-e',errorjs,pkg],env=failed).stdout);ce=json.loads(call('CLI safe missing/no fallback',[cli,'config','resolve'],env=failed,code=1).stderr);assert ne==ce==pyerror and set(ce)=={'code','message'}
    assert before==(config.read_bytes(),config.stat().st_mtime_ns,explicit.read_bytes(),explicit.stat().st_mtime_ns)
    assert meta()==before_identity and peerwork.open_identity(str(identity))==public
    assert sorted(p.name for p in parent.iterdir())==['config.json','profile 用户']
    print(json.dumps(dict(result='PASS',uid=os.getuid(),euid=os.geteuid(),gid=os.getegid(),source='a1488b84290b519eafa4c9f019412e7abe94c991',python={'runtime':sys.version,'wrapper':peerwork.__file__,'native':native.__file__,'version':peerwork.version()},node=n,shared_identity=public,readonly_config_unchanged=True,identity_metadata_unchanged=True,no_http=True,error=ce,calls=calls)))

def host(base):
    base=Path(base).resolve();root=base/'rootfs';home=root/HOME.lstrip('/');home.mkdir(mode=0o700);os.chown(home,65534,65534);shutil.copy2(__file__,home/'smoke.py');os.chown(home/'smoke.py',65534,65534)
    argv=['chroot','--userspec=65534:65534',str(root),'/usr/bin/env','-i','HOME='+HOME,'PATH=/opt/node24/bin:/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1','/opt/python/cp311-cp311/bin/python','-I',HOME+'/smoke.py','--child']
    (base/'config-smoke-invocation.json').write_text(json.dumps(argv,indent=2)+'\n');t=time.monotonic();start=datetime.datetime.now(datetime.timezone.utc)
    with (base/'config-smoke.stdout').open('w')as out,(base/'config-smoke.stderr').open('w')as err:r=subprocess.run(argv,stdout=out,stderr=err)
    (base/'config-smoke-terminal.json').write_text(json.dumps(dict(exit_code=r.returncode,start_utc=start.isoformat(),end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-t))+'\n');raise SystemExit(r.returncode)
if __name__=='__main__':child()if'--child'in sys.argv else host(sys.argv[1])
