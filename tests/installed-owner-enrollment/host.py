"""Three installed interfaces under the archived no-model runtime policy."""
import hashlib,json,os,selectors,shutil,sqlite3,subprocess,sys
from pathlib import Path
if len(sys.argv)!=4:raise SystemExit('usage: host.py COHORT_DIRECTORY CODEX NEW_TASK_DIRECTORY')
cohort,codex,task=map(lambda p:Path(p).absolute(),sys.argv[1:]);metadata=json.loads((cohort/'cohort-source.json').read_text())
assert metadata['source_commit']=='8900e8066ef8d07117a3b85771e831e4f84ffba8'
assert 'PEERWORK_HTTP_PROXY' not in os.environ,'runner must not preselect SDK proxy'
assert codex.is_file() and not task.exists();task.mkdir(mode=0o700)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sdk=Path(metadata['sdk_host_path']);rootfs=sdk.parent.parent
source_manifest=cohort/'source-manifest-8900e80.sha256';artifact_manifest=cohort/'artifact-manifest.sha256'
assert sha(source_manifest)==metadata['source_manifest_sha256'] and len(source_manifest.read_text().splitlines())==584
assert sha(cohort/'sdk-source-8900e80.tar')==metadata['source_archive_sha256'] and len(artifact_manifest.read_text().splitlines())==14
artifact_hash=sha(artifact_manifest)
def verify_cohort():
 assert sha(artifact_manifest)==artifact_hash
 subprocess.run(['sha256sum','-c','--status',str(source_manifest)],cwd=sdk,check=True)
 subprocess.run(['sha256sum','-c','--status',str(artifact_manifest)],cwd=cohort,check=True)
verify_cohort()
archive=Path('/root/workdir/message/.test-data/agent-wiki-natural-20261015-ready/observer/agent-attempt-1/invocation.json')
assert sha(archive)=='52855bcd47d2da7d91577bf6ac31f47964d6a75fe5e973e4bfe93b1f36588cf2'
original=json.loads(archive.read_text())['argv'];policy=[original[i+1] for i,a in enumerate(original) if a=='-c'];assert len(policy)==18
assert 'permissions.trial.network.domains={"127.0.0.1"="allow"}' in policy and 'permissions.trial.network.allow_upstream_proxy=false' in policy
reference=Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006');assert subprocess.check_output(['git','-C',str(reference),'rev-parse','HEAD'],text=True).strip()=='f828b6c50a0a58d1e718af90f653b214adcc3328'
compiled=reference/'dist-workspace/src';files=sorted(compiled.rglob('*.js'));digest=hashlib.sha256()
for file in files:digest.update(str(file.relative_to(compiled)).encode()+b'\0'+hashlib.sha256(file.read_bytes()).hexdigest().encode()+b'\n')
assert len(files)==204 and digest.hexdigest()=='6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc'
node=rootfs/'opt/node24/bin/node';scripts=Path(__file__).resolve().parent
for name in ['adapter.py','child.py']:
 target=task/name;shutil.copyfile(scripts/name,target);target.chmod(0o600)
results=[]
for interface in ['python','node','cli']:
 case=task/interface;case.mkdir(mode=0o700);service=case/'service';service.mkdir(mode=0o700)
 request_log=case/'requests.jsonl';request_log.touch(mode=0o600)
 env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(reference),PEERWORK_TEST_STATE=str(service),PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(request_log),PYTHONDONTWRITEBYTECODE='1')
 log=service/'stderr.log';log.touch(mode=0o600);stderr=log.open('wb');process=None
 terminal=dict(interface=interface,result='FAIL')
 try:
  process=subprocess.Popen([str(node),'--require',str(sdk/'tests/historical-direct-request-observer.cjs'),str(sdk/'tests/reference-kernel-server.mjs')],env=env,cwd=sdk,stdout=subprocess.PIPE,stderr=stderr,text=True)
  selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
  try:
   if not selector.select(60):raise RuntimeError('fixture READY timeout; protected service stderr retained')
   ready=json.loads(process.stdout.readline())
  finally:selector.close()
  config=case/'owner-config.json';config.write_text(json.dumps(dict(origin=ready['origin'],state_dir=str(case/'native'),allow_loopback_http=True))+'\n');config.chmod(0o600)
  pem=case/'selected-owner.pem';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(pem)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);pem.chmod(0o600)
  imported=subprocess.run([sys.executable,'-I','-B',str(task/'adapter.py'),interface,str(sdk),'identity-import',str(config),str(pem)],env=env,capture_output=True,text=True,timeout=30)
  for suffix,value in [('stdout',imported.stdout),('stderr',imported.stderr)]:
   p=case/('identity-import.'+suffix);p.write_text(value);p.chmod(0o600)
  assert imported.returncode==0,'installed identity import failed'
  request=case/'workspace-input.json';request.write_text(json.dumps(dict(name='Installed Owner enrollment proxy '+interface,visibility='PRIVATE',structured=True))+'\n');request.chmod(0o600)
  argv=[str(codex),'sandbox','-P','trial','-C',str(case)]
  for setting in policy:argv.extend(['-c',setting])
  argv.extend([sys.executable,'-I','-B',str(task/'child.py'),str(task/'adapter.py'),interface,str(sdk),str(case)])
  invocation=dict(argv=argv,archived_policy_sha256=sha(archive),policy_equal_to_archived_capture=True,cohort_source=metadata['source_commit'],artifact_manifest_sha256=artifact_hash,codex_sha256=sha(codex.resolve()),child_sha256=sha(task/'child.py'),adapter_sha256=sha(task/'adapter.py'),no_model=True,scope='host Linux runtime policy; installed wheel/npm/CLI from the glibc2.28 cohort; no chroot runtime-platform inference')
  p=case/'invocation.json';p.write_text(json.dumps(invocation,indent=2)+'\n');p.chmod(0o600)
  completed=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=300)
  for suffix,value in [('stdout',completed.stdout),('stderr',completed.stderr)]:
   p=case/('runtime.'+suffix);p.write_text(value);p.chmod(0o600)
  terminal['exit_code']=completed.returncode
  if completed.returncode==0:
   result=json.loads((case/'child-summary.json').read_text());assert result['result']=='PASS' and result['interface']==interface
   with sqlite3.connect('file:'+str(service/'control.sqlite')+'?mode=ro',uri=True) as db:
    workspace_count=db.execute('SELECT count(*) FROM secure_workspaces').fetchone()[0];commits=db.execute('SELECT sequence,action_id FROM secure_commits ORDER BY sequence').fetchall()
   assert workspace_count==1 and commits==[(1,'secure.bootstrap')]
   terminal.update(result='PASS',workspaces=workspace_count,service_commits=len(commits),checks=result)
 except Exception as error:
  # Never interpolate raw SDK/subprocess errors, output or runtime proxy URLs.
  terminal['failure_kind']=type(error).__name__
 finally:
  if process is not None:
   if process.poll() is None:
    process.terminate()
    try:process.wait(timeout=10)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
   terminal['service_exit_code']=process.returncode
  stderr.close();terminal['service_stderr_sha256']=sha(log)
  p=service/'exit.json';p.write_text(json.dumps(dict(exit_code=terminal.get('service_exit_code'),stderr_sha256=sha(log)))+'\n');p.chmod(0o600)
  verify_cohort()
 results.append(terminal);print(json.dumps(terminal),flush=True)
p=task/'summary.json';p.write_text(json.dumps(dict(source=metadata['source_commit'],classification='operator_synthetic',interfaces=results),indent=2)+'\n');p.chmod(0o600)
assert len(results)==3 and all(row['result']=='PASS' for row in results),'installed enrollment cases failed; protected evidence retained'
