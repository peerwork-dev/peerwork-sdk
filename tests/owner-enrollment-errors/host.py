"""Real Owner enrollment over the preserved runtime policy; no model or actor."""
import hashlib,json,os,selectors,shutil,sqlite3,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
if len(sys.argv)!=4:raise SystemExit('usage: host.py CURRENT_CLI CODEX NEW_TASK_DIRECTORY')
cli,codex,task=map(lambda p:Path(p).absolute(),sys.argv[1:]);assert cli.is_file() and codex.is_file() and not task.exists()
task.mkdir(mode=0o700);service=task/'service';service.mkdir(mode=0o700)
archive=Path('/root/workdir/message/.test-data/agent-wiki-natural-20261015-ready/observer/agent-attempt-1/invocation.json')
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='52855bcd47d2da7d91577bf6ac31f47964d6a75fe5e973e4bfe93b1f36588cf2'
original=json.loads(archive.read_text())['argv'];policy=[original[i+1] for i,a in enumerate(original) if a=='-c'];assert len(policy)==18
assert 'permissions.trial.network.domains={"127.0.0.1"="allow"}' in policy and 'permissions.trial.network.allow_upstream_proxy=false' in policy
reference=Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006');assert subprocess.check_output(['git','-C',str(reference),'rev-parse','HEAD'],text=True).strip()=='f828b6c50a0a58d1e718af90f653b214adcc3328'
subprocess.run(['git','-C',str(reference),'diff','--quiet','HEAD','--','src','tests','protocols','package.json','package-lock.json'],check=True)
compiled=reference/'dist-workspace/src';files=sorted(compiled.rglob('*.js'));digest=hashlib.sha256()
for file in files:digest.update(str(file.relative_to(compiled)).encode()+b'\0'+hashlib.sha256(file.read_bytes()).hexdigest().encode()+b'\n')
assert len(files)==204 and digest.hexdigest()=='6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc'
node=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/current-sdk-c5e7a3d/rootfs/opt/node24/bin/node').resolve()
request_log=task/'requests.jsonl';request_log.touch(mode=0o600)
env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(reference),PEERWORK_TEST_STATE=str(service),PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(request_log));env.pop('PEERWORK_HTTP_PROXY',None)
log=service/'stderr.log';log.touch(mode=0o600);stderr=log.open('wb')
process=subprocess.Popen([str(node),'--require',str(ROOT/'tests/historical-direct-request-observer.cjs'),str(ROOT/'tests/reference-kernel-server.mjs')],env=env,cwd=ROOT,stdout=subprocess.PIPE,stderr=stderr,text=True)
try:
 selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
 try:
  if not selector.select(60):raise RuntimeError('fixture READY timeout; protected service stderr retained')
  ready=json.loads(process.stdout.readline())
 finally:selector.close()
 config=task/'owner-config.json';config.write_text(json.dumps(dict(origin=ready['origin'],state_dir=str(task/'native'),allow_loopback_http=True))+'\n');config.chmod(0o600)
 pem=task/'selected-owner.pem';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(pem)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);pem.chmod(0o600)
 imported=subprocess.run([str(cli),'identity','import-legacy-owner-pem',str(config),str(pem)],capture_output=True,text=True,timeout=30)
 for suffix,value in [('stdout',imported.stdout),('stderr',imported.stderr)]:
  p=task/('identity-import.'+suffix);p.write_text(value);p.chmod(0o600)
 assert imported.returncode==0
 request=task/'workspace-input.json';request.write_text(json.dumps(dict(name='Owner enrollment proxy regression',visibility='PRIVATE',structured=True))+'\n');request.chmod(0o600)
 child=task/'child.py';shutil.copyfile(Path(__file__).with_name('child.py'),child);child.chmod(0o600)
 argv=[str(codex),'sandbox','-P','trial','-C',str(task)]
 for setting in policy:argv.extend(['-c',setting])
 argv.extend([sys.executable,str(child),str(cli),str(task)])
 invocation=dict(argv=argv,archived_policy_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),policy_equal_to_archived_capture=True,cli_sha256=hashlib.sha256(cli.read_bytes()).hexdigest(),codex_sha256=hashlib.sha256(codex.resolve().read_bytes()).hexdigest(),child_sha256=hashlib.sha256(child.read_bytes()).hexdigest(),no_model=True)
 p=task/'invocation.json';p.write_text(json.dumps(invocation,indent=2)+'\n');p.chmod(0o600)
 completed=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=300)
 for suffix,value in [('stdout',completed.stdout),('stderr',completed.stderr)]:
  p=task/('runtime.'+suffix);p.write_text(value);p.chmod(0o600)
 assert completed.returncode==0,'deterministic runtime failed; protected runtime stderr retained'
 result=json.loads((task/'child-summary.json').read_text());assert result['result']=='PASS'
 with sqlite3.connect('file:'+str(service/'control.sqlite')+'?mode=ro',uri=True) as db:
  workspace_count=db.execute('SELECT count(*) FROM secure_workspaces').fetchone()[0]
  commits=db.execute('SELECT sequence,action_id FROM secure_commits ORDER BY sequence').fetchall()
 assert workspace_count==1 and commits==[(1,'secure.bootstrap')]
 result.update(workspaces=workspace_count,service_commits=len(commits),scope='same-runtime current CLI real enrollment/create/read; no natural Agent or installed Python/Node result')
 p=task/'summary.json';p.write_text(json.dumps(result,indent=2)+'\n');p.chmod(0o600)
 print(json.dumps(result),flush=True)
finally:
 if process.poll() is None:
  process.terminate()
  try:process.wait(timeout=10)
  except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
 stderr.close()
 p=service/'exit.json';p.write_text(json.dumps(dict(exit_code=process.returncode,stderr_sha256=hashlib.sha256(log.read_bytes()).hexdigest()))+'\n');p.chmod(0o600)
