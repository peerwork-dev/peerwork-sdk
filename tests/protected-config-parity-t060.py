#!/usr/bin/env python3
"""Compiled-local resolver parity under actual non-root Unix permissions; no network."""
from pathlib import Path
import os,sys,json,hashlib,subprocess,shutil,time,datetime
ROOT=Path('/tmp/peerwork-t060-protected-config-20261015')

def child():
    assert os.geteuid()==65534 and os.getegid()==65534
    os.umask(0o077);user=ROOT/'user home 用户';user.mkdir(mode=0o700);os.chdir(user)
    py=ROOT/'public/python';pkg=ROOT/'public/node/node_modules/@peerwork/agent-sdk';cli=ROOT/'public/peerwork';node=ROOT/'public/node-bin'
    def directory(path):path.mkdir(mode=0o700,parents=True,exist_ok=True);return path
    def config(path,origin):directory(path.parent);path.write_text(json.dumps({'origin':origin,'state_dir':'profile 用户'}));path.chmod(0o600);return path
    home=directory(user/'HOME');xdg=directory(user/'xdg');explicit=config(user/'explicit/config.json','https://explicit.invalid');ep=config(user/'env/config.json','https://env.invalid');xp=config(xdg/'peerwork/config.json','https://xdg.invalid');hp=config(home/'.config/peerwork/config.json','https://home.invalid')
    env=dict(os.environ,HOME=str(home),XDG_CONFIG_HOME=str(xdg));env.pop('PEERWORK_CONFIG',None)
    cases=[];source_before={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in [explicit,ep,xp,hp]}
    pycode='import sys,json;sys.path.insert(0,sys.argv[1]);import peerwork;\ntry: print(json.dumps(peerwork.load_config(sys.argv[2] if len(sys.argv)>2 else None)))\nexcept peerwork.ConfigError as e: print(json.dumps({"code":e.code,"message":str(e)}));sys.exit(7)'
    jscode='const s=require(process.argv[1]);s.loadConfig(process.argv[2]).then(v=>console.log(JSON.stringify(v))).catch(e=>{console.log(JSON.stringify({code:e.code,message:e.message}));process.exitCode=7})'
    def check(label,path=None,envvars=None,code=None,selected=None):
        vars=env if envvars is None else envvars
        for interface in ['python','node','cli']:
            cmd=[sys.executable,'-I','-c',pycode,str(py)] if interface=='python' else [str(node),'-e',jscode,str(pkg)] if interface=='node' else [str(cli),'config','resolve']
            if path is not None:cmd.append(str(path))
            before={str(p.relative_to(user)) for p in user.rglob('*')}
            r=subprocess.run(cmd,env=vars,text=True,capture_output=True);value=json.loads(r.stderr if interface=='cli' and r.returncode else r.stdout)
            if code:
                assert r.returncode==(1 if interface=='cli' else 7),(label,interface,r.returncode,r.stderr)
                assert set(value)=={'code','message'} and value['code']==code,(label,interface,value)
                assert all(x not in value['message'] for x in ['rejected-secret-sentinel','https://u:p@','config.json',str(user)])
                if interface=='cli':assert not r.stdout
            else:
                assert r.returncode==0,(label,interface,r.stderr)
                expected=json.loads(selected.read_text());expected['state_dir']=str(selected.parent/expected['state_dir'])
                if interface=='node':expected['stateDir']=expected.pop('state_dir')
                assert value==expected,(label,interface,value,expected)
            assert before=={str(p.relative_to(user)) for p in user.rglob('*')},(label,'unexpected writes')
            cases.append(dict(label=label,interface=interface,returncode=r.returncode,result=value))
    check('XDG default',selected=xp)
    withoutxdg=dict(env);withoutxdg.pop('XDG_CONFIG_HOME');check('HOME fallback',envvars=withoutxdg,selected=hp)
    envpin=dict(env,PEERWORK_CONFIG=str(ep));check('environment selection',envvars=envpin,selected=ep)
    check('explicit overrides env',path=explicit,envvars=dict(envpin,PEERWORK_CONFIG='/missing/ignored'),selected=explicit)
    check('explicit relative file',path='explicit/config.json',envvars=envpin,selected=explicit)
    check('selected missing no fallback',envvars=dict(envpin,PEERWORK_CONFIG=str(ep.parent/'missing.json')),code='CONFIG_MISSING')
    check('explicit missing no fallback',path=explicit.parent/'missing.json',envvars=envpin,code='CONFIG_MISSING')
    check('empty env no fallback',envvars=dict(envpin,PEERWORK_CONFIG=''),code='CONFIG_LOCATION')
    check('relative OS root refused',envvars=dict(env,XDG_CONFIG_HOME='relative'),code='CONFIG_LOCATION')
    unsafe=config(user/'unsafe/config.json','https://unsafe.invalid');unsafe.chmod(0o644);check('unsafe mode',path=unsafe,code='CONFIG_UNSAFE')
    link=user/'explicit/link.json';link.symlink_to(explicit);check('symlink',path=link,code='CONFIG_UNSAFE')
    bad=user/'explicit/bad.json';bad.write_text('{"origin":"https://u:p@control.invalid","state_dir":"profile 用户"}');bad.chmod(0o600);check('credentials refused',path=bad,code='CONFIG_INVALID')
    bad.write_text('{"origin":"https://control.invalid","state_dir":"profile 用户","seed":"rejected-secret-sentinel"}');check('unknown secret field refused',path=bad,code='CONFIG_INVALID')
    bad.write_text(' '*16385);check('bounded read',path=bad,code='CONFIG_LIMIT')
    readonly=config(user/'readonly/config.json','https://readonly.invalid');readonly.chmod(0o400);readonly.parent.chmod(0o500);check('nonroot readonly config',path=readonly,selected=readonly);readonly.parent.chmod(0o700)
    for p,(wire,mtime) in source_before.items():assert p.read_bytes()==wire and p.stat().st_mtime_ns==mtime
    assert not list(user.rglob('identity.state')) and not list(user.rglob('*.lock'))
    print(json.dumps(dict(result='PASS',uid=os.getuid(),euid=os.geteuid(),gid=os.getegid(),groups=os.getgroups(),cases=cases,no_identity_or_locks=True,config_source_bytes_mtime_unchanged=True)))

def host():
    base=Path.cwd();evidence=base/'.test-data/t060';assert not ROOT.exists();ROOT.mkdir(mode=0o755)
    public=ROOT/'public';public.mkdir(mode=0o755);py=public/'python/peerwork';py.mkdir(parents=True);shutil.copy2(base/'bindings/python/peerwork/__init__.py',py/'__init__.py');shutil.copy2(base/'.build-target/debug/lib_peerwork_native.so',py/'_peerwork_native.abi3.so')
    pkg=public/'node/node_modules/@peerwork/agent-sdk';pkg.mkdir(parents=True);shutil.copy2(base/'bindings/node/index.cjs',pkg/'index.cjs');(pkg/'package.json').write_text('{"main":"index.cjs"}')
    platform=pkg.parent/'agent-sdk-linux-x64-gnu';platform.mkdir();shutil.copy2(base/'.build-target/debug/libpeerwork_node_native.so',platform/'index.node');(platform/'package.json').write_text('{"main":"index.node"}')
    shutil.copy2(base/'.build-target/debug/peerwork',public/'peerwork');shutil.copy2('/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node',public/'node-bin');shutil.copy2(__file__,public/'runner.py')
    # Package files are public; only fresh fixture/config directories are private.
    for p in public.rglob('*'):p.chmod(0o755 if p.is_dir() or p.name in ['peerwork','node-bin'] else 0o644)
    os.chown(ROOT,65534,65534)
    argv=['setpriv','--reuid=65534','--regid=65534','--clear-groups',sys.executable,'-I',str(public/'runner.py'),'--child']
    (evidence/'parity-invocation.json').write_text(json.dumps(argv,indent=2)+'\n');t=time.monotonic();start=datetime.datetime.now(datetime.timezone.utc)
    with (evidence/'parity.stdout').open('w') as out,(evidence/'parity.stderr').open('w') as err:r=subprocess.run(argv,stdout=out,stderr=err,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
    (evidence/'parity-terminal.json').write_text(json.dumps(dict(exit_code=r.returncode,elapsed_seconds=time.monotonic()-t,start_utc=start.isoformat(),end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))+'\n')
    subjects=[base/'.build-target/debug/peerwork',base/'.build-target/debug/lib_peerwork_native.so',base/'.build-target/debug/libpeerwork_node_native.so',py/'_peerwork_native.abi3.so',platform/'index.node',public/'peerwork']
    (evidence/'local-binaries.json').write_text(json.dumps([dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),size=p.stat().st_size) for p in subjects],indent=2)+'\n')
    raise SystemExit(r.returncode)
if __name__=='__main__':child() if '--child' in sys.argv else host()
