#!/usr/bin/env python3
"""T057: explicit protected paths and offline installs under a real non-root UID."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,sys,time,datetime,stat
SOURCE='7dd319713708c417e5bc6026be1cf32ca598cfde'
GUEST='/work/sdk-marker-t023-20261015'
HOME='/work/t057 非root home'

def child():
    assert os.geteuid()==65534 and os.getegid()==65534
    os.umask(0o077)
    home=Path(HOME);os.chdir(home);install=home/'用户 install space';install.mkdir(mode=0o700)
    py=install/'python site';node=install/'node packages';bin=install/'bin';bin.mkdir()
    cli=bin/'peerwork';shutil.copy2(GUEST+'/target/release/peerwork',cli)
    calls=[]
    def run(label,args,expect=0,env=None):
        r=subprocess.run([str(x) for x in args],text=True,capture_output=True,env=env)
        calls.append(dict(label=label,argv=[str(x) for x in args],returncode=r.returncode,stdout=r.stdout,stderr=r.stderr))
        assert r.returncode==expect,(label,r.returncode,r.stderr)
        return r
    wheel=next(Path(GUEST+'/dist/wheels').glob('*.whl'))
    run('offline wheel',[sys.executable,'-m','pip','install','--no-index','--no-deps','--target',py,wheel])
    node.mkdir();(node/'package.json').write_text('{"name":"nonadmin-offline","private":true}')
    run('offline npm',['/opt/node24/bin/node','/opt/node24/lib/node_modules/npm/bin/npm-cli.js','install','--prefix',node,'--offline','--ignore-scripts','--no-audit','--no-fund','--no-save',GUEST+'/dist/npm/peerwork-agent-sdk-0.0.1.tgz',GUEST+'/dist/npm/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz'])
    pkg=node/'node_modules/@peerwork/agent-sdk'
    prefix='import sys,json;sys.path.insert(0,sys.argv[1]);import peerwork;'
    def python(label,code,*args,**kw):return run(label,[sys.executable,'-I','-c',prefix+code,py,*args],**kw)
    def js(label,code,*args,**kw):return run(label,['/opt/node24/bin/node','-e','const s=require(process.argv[1]);'+code,pkg,*args],**kw)
    profile=home/'明确 state 目录';profile.mkdir(mode=0o700);identity=profile/'identity.state'
    made=json.loads(python('python identity create','print(json.dumps(peerwork.create_identity(sys.argv[2])))',identity).stdout)
    meta=lambda f:(f.stat().st_ino,f.stat().st_size,f.stat().st_mtime_ns,stat.S_IMODE(f.stat().st_mode),f.stat().st_uid)
    original=meta(identity)
    assert json.loads(js('node reopen',"s.openIdentity(process.argv[2]).then(v=>console.log(JSON.stringify(v)))",identity).stdout)==made
    assert json.loads(run('cli reopen',[cli,'identity','info',identity]).stdout)==made
    relative=str(identity.relative_to(home));assert json.loads(run('cli relative reopen',[cli,'identity','info',relative]).stdout)==made
    config=home/'selected config.json';config.write_text(json.dumps(dict(origin='https://control.invalid',state_dir=str(profile))))
    other=home/'other HOME';other.mkdir(mode=0o700);xdg=other/'config';xdg.mkdir(mode=0o700)
    env=dict(os.environ,HOME=str(other),XDG_CONFIG_HOME=str(xdg));config_names=list(xdg.iterdir())
    assert json.loads(python('explicit Python state with changed HOME',"print(json.dumps(peerwork.SecureOwnerWorkspaceClient('https://control.invalid',sys.argv[2]).operations()))",profile,env=env).stdout)==[]
    assert json.loads(js('explicit Node state with changed HOME',"s.openSecureOwnerWorkspaces({origin:'https://control.invalid',stateDir:process.argv[2]}).operations().then(v=>console.log(JSON.stringify(v)))",profile,env=env).stdout)==[]
    assert json.loads(run('explicit CLI config with changed HOME',[cli,'secure','owner-operations',config],env=env).stdout)==[]
    assert list(xdg.iterdir())==config_names and list(other.iterdir())==[xdg]
    # No automatic discovery is asserted: missing explicit public arguments refuse.
    assert json.loads(python('Python missing config',"\ntry: peerwork.SecureOwnerWorkspaceClient()\nexcept TypeError: print(json.dumps({'error':'TypeError'}))",env=env).stdout)=={'error':'TypeError'}
    assert json.loads(js('Node missing config',"try{s.openSecureOwnerWorkspaces({});throw Error('accepted')}catch(e){if(!(e instanceof TypeError))throw e;console.log(JSON.stringify({error:e.name}))}",env=env).stdout)=={'error':'TypeError'}
    r=run('CLI missing config',[cli,'secure','owner-operations'],expect=1,env=env);assert json.loads(r.stderr)['code']=='USAGE' and not r.stdout
    readonly=home/'readonly protected';readonly.mkdir(mode=0o700)
    kept=readonly/'identity.state';saved=json.loads(python('readonly seed via public API','print(json.dumps(peerwork.create_identity(sys.argv[2])))',kept).stdout);before=meta(kept)
    readonly.chmod(0o500);names=sorted(f.name for f in readonly.iterdir())
    readonly_errors=[]
    for language in ['python','node','cli']:
        target=readonly/(language+' absent.state')
        if language=='python':
            r=python('readonly Python',"\ntry: peerwork.create_identity(sys.argv[2]);raise AssertionError('accepted')\nexcept RuntimeError as e: print(json.dumps({'error':str(e)}))",target);value=json.loads(r.stdout);assert value['error']=='local secure-agent state operation failed'
        elif language=='node':
            r=js('readonly Node',"s.createIdentity(process.argv[2]).then(()=>{throw Error('accepted')}).catch(e=>{console.log(JSON.stringify({error:e.message}));})",target);value=json.loads(r.stdout);assert value['error']=='local secure-agent state operation failed'
        else:
            r=run('readonly CLI',[cli,'identity','create',target],expect=1);value=json.loads(r.stderr);assert value=={'code':'IDENTITY_STATE','message':'local secure-agent state operation failed'} and not r.stdout
        readonly_errors.append(dict(interface=language,result=value));assert not target.exists() and sorted(f.name for f in readonly.iterdir())==names and meta(kept)==before
    readonly.chmod(0o700)
    assert json.loads(run('readonly identity unchanged public reopen',[cli,'identity','info',kept]).stdout)==saved
    assert meta(identity)==original and json.loads(python('final original identity reopen','print(json.dumps(peerwork.open_identity(sys.argv[2])))',identity).stdout)==made
    imports=json.loads(python('actual Python module',"import peerwork._peerwork_native as n;print(json.dumps({'wrapper':peerwork.__file__,'native':n.__file__,'version':peerwork.version(),'runtime':sys.version}))").stdout)
    nodes=json.loads(js('actual Node module',"console.log(JSON.stringify({wrapper:require.resolve(process.argv[1]),native:Object.keys(require.cache).filter(x=>x.endsWith('.node')),version:s.version(),runtime:process.version}))").stdout)
    summary=dict(result='PASS',source=SOURCE,uid=os.getuid(),euid=os.geteuid(),gid=os.getegid(),groups=os.getgroups(),home=HOME,python=imports,node=nodes,cli=str(cli),shared_identity_public_ids=made,identity_metadata_unchanged=True,explicit_config_with_changed_home=True,automatic_home_discovery='UNVERIFIED: current APIs require explicit arguments; missing-input refusal observed',readonly_errors=readonly_errors,calls=calls)
    (home/'result.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({k:v for k,v in summary.items() if k!='calls'}))

def host(base):
    base=Path(base).resolve();base.mkdir(mode=0o700)
    cohort=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/marker-sdk-t023-20261015');root=(cohort/'rootfs').resolve();home=root/HOME.lstrip('/')
    subprocess.run(['sha256sum','-c','--status',str(cohort/'artifact-manifest.sha256')],cwd=cohort,check=True)
    assert hashlib.sha256((cohort/'artifact-manifest.sha256').read_bytes()).hexdigest()=='85aa7882e72280b896fc3d127627265bc9dbcecd0a2df51c9af40818b5433ea6'
    assert home.is_dir() and not list(home.iterdir())
    task=home/'task.py';shutil.copyfile(__file__,task);os.chown(task,65534,65534);task.chmod(0o600)
    argv=['chroot','--userspec=65534:65534',str(root),'/usr/bin/env','-i','HOME='+HOME,'PATH=/opt/node24/bin:/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1','/opt/python/cp311-cp311/bin/python','-I',HOME+'/task.py','--child']
    (base/'invocation.json').write_text(json.dumps(dict(argv=argv,source=SOURCE,cohort=str(cohort),no_network=True),indent=2)+'\n')
    t=time.monotonic();start=datetime.datetime.now(datetime.timezone.utc)
    with (base/'stdout.log').open('w') as out,(base/'stderr.log').open('w') as err:r=subprocess.run(argv,cwd='/',stdout=out,stderr=err)
    (base/'terminal.json').write_text(json.dumps(dict(exit_code=r.returncode,elapsed_seconds=time.monotonic()-t,start_utc=start.isoformat(),end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))+'\n')
    if (home/'result.json').exists():shutil.copyfile(home/'result.json',base/'result.json')
    subprocess.run(['sha256sum','-c','--status',str(cohort/'artifact-manifest.sha256')],cwd=cohort,check=True)
    subprocess.run(['sha256sum','-c','--status',str(cohort/'source-manifest-final.sha256')],cwd=root/GUEST.lstrip('/'),check=True)
    (base/'post-guards.json').write_text(json.dumps(dict(artifact14='PASS',source687='PASS',test_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))+'\n')
    raise SystemExit(r.returncode)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--child',action='store_true');p.add_argument('--evidence');a=p.parse_args();child() if a.child else host(a.evidence)
