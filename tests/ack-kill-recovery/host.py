"""Three independent installed official proposal/adoption/task journeys."""
from pathlib import Path
import hashlib,json,os,selectors,sqlite3,subprocess,sys,shutil,time,signal,urllib.request
BASE=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/marker-sdk-t023-20261015');ROOT=(BASE/'rootfs').resolve();SDK=ROOT/'work/sdk-marker-t023-20261015';GSDK='/work/sdk-marker-t023-20261015'
REFERENCE=Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006');HERE=Path(__file__).resolve().parent;NODE=ROOT/'opt/node24/bin/node'
SOURCE='7dd319713708c417e5bc6026be1cf32ca598cfde';SOURCE_SHA='9e2900b85d4097ab3e3b0e9f403f5a56ff22442a3e90df857e6f83f91d083e0e';ARTIFACT=os.environ['PEERWORK_MARKER_ARTIFACT_MANIFEST_SHA256']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def guard():
 assert sha(BASE/'source-manifest-final.sha256')==SOURCE_SHA
 assert sha(BASE/'artifact-manifest.sha256')==ARTIFACT
 subprocess.run(['sha256sum','-c','--status',str(BASE/'source-manifest-final.sha256')],cwd=SDK,check=True)
 subprocess.run(['sha256sum','-c','--status',str(BASE/'artifact-manifest.sha256')],cwd=BASE,check=True)
guard();assert subprocess.check_output(['git','-C',str(REFERENCE),'rev-parse','HEAD'],text=True).strip()=='f828b6c50a0a58d1e718af90f653b214adcc3328'
name=sys.argv[1]if len(sys.argv)>1 else'ack-kill-recovery-first';assert name.replace('-','').isalnum();state=ROOT/'work'/name;state.mkdir(mode=0o700)
empty=state/'empty-runtimes';empty.mkdir(mode=0o700)
for file in ['python.py','node.cjs']:shutil.copyfile(HERE.parent/'official-independent'/file,state/file);(state/file).chmod(0o600)
proxy_overlay=state/'reference-overlay.mjs';overlay_meta=subprocess.check_output([sys.executable,str(HERE/'overlay.py'),str(SDK/'tests/reference-kernel-server.mjs'),str(proxy_overlay),str(state/'ack-events.jsonl')],text=True);(state/'overlay.json').write_text(overlay_meta);(state/'overlay.json').chmod(0o600)
vector=json.loads((SDK/'conformance/official-proposal-task-composition.json').read_text());assert vector['root_package_digest'] and vector['protocol_digest']
results=[]
# Each invocation gets a private mount namespace. Host HTTP and orchestration
# stay outside; no language runtime executes on behalf of a different client.
program=r'''root="$1";empty="$2";kind="$3";shift 3
mount --make-rprivate /
for device in null zero urandom;do mount --bind "/dev/$device" "$root/dev/$device";done
if [ "$kind" != python ];then
 for path in usr/bin/python3.12;do mount --bind /dev/null "$root/$path";done
 for path in opt/python usr/local/bin usr/libexec;do mount --bind "$empty" "$root/$path";done
 for path in /opt/python/cp311-cp311/bin/python /usr/bin/python3.12 /usr/bin/python3 /usr/bin/unversioned-python /usr/libexec/platform-python /usr/local/bin/python3.14;do
  if chroot "$root" "$path" --version >/dev/null 2>&1;then echo UNEXPECTED_PYTHON >&2;exit 71;fi
 done
fi
if [ "$kind" != node ];then
 mount --bind "$empty" "$root/opt/node24"
 if chroot "$root" /opt/node24/bin/node --version >/dev/null 2>&1;then echo UNEXPECTED_NODE >&2;exit 72;fi
fi
exec chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/work/sdk-marker-t023-20261015/dist/python-consumer PEERWORK_TEST_SDK_ROOT=/work/sdk-marker-t023-20261015 "$@"
'''
for mode in ['cli']:
 interface='cli';case=state/mode;case.mkdir(mode=0o700);(case/'calls').mkdir(mode=0o700);kernel=case/'kernel';kernel.mkdir(mode=0o700);err=kernel/'stderr.log';err.touch(mode=0o600);errstream=err.open('wb');requestlog=case/'requests.jsonl';requestlog.touch(mode=0o600)
 env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(REFERENCE),PEERWORK_TEST_STATE=str(kernel),PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(requestlog),PEERWORK_ACK_EVENTS=str(case/'ack-events.jsonl'),PEERWORK_ACK_RESPONSE=str(case/'ack-response.bin'))
 server=subprocess.Popen([str(NODE),'--require',str(SDK/'tests/historical-direct-request-observer.cjs'),str(proxy_overlay)],env=env,stdout=subprocess.PIPE,stderr=errstream,text=True)
 def guest(p):return'/'+str(p.relative_to(ROOT))
 calls=[]
 def invoke(op,c,input=None,workspace=None,command=None,expect_error=False):
  n=len(calls);p=case/'calls'/f'{n:03d}.json';r=dict(op=op,config=c,input=input or{},workspace=workspace,command=command);p.write_text(json.dumps(r));p.chmod(0o600)
  conf=case/'calls'/f'{n:03d}-config.json';conf.write_text(json.dumps(c));conf.chmod(0o600)
  inp=case/'calls'/f'{n:03d}-input.json';x=input or{};inp.write_text(json.dumps(x));inp.chmod(0o600)
  selected_interface='cli'if mode=='python-cli-handoff'and op=='owner-status'and command=='p'*43 else interface
  if selected_interface=='python':argv=['/opt/python/cp311-cp311/bin/python',guest(state/'python.py'),guest(p)]
  elif selected_interface=='node':argv=['/opt/node24/bin/node',guest(state/'node.cjs'),guest(p)]
  else:
   cli=GSDK+'/target/release/peerwork';cfg=guest(conf);ip=guest(inp)
   if op=='runtime':argv=[cli,'capabilities']
   elif op=='identity':argv=[cli,'identity','info',c['state_dir']+'/identity.state']
   elif op in ['recipient-create','recipient-publish']:argv=[cli,'secure',op,'--origin='+c['origin'],'--state-dir='+c['state_dir'],'--allow-loopback-http']
   elif op=='lookup':argv=[cli,'secure','directory-lookup','--origin='+c['origin'],'--state-dir='+c['state_dir'],'--actor='+x['actor_id'],'--key='+x['key_id'],'--allow-loopback-http']
   else:
    if op=='prepare':args=['owner-prepare',cfg,ip];inp.write_text(json.dumps(dict(name='Independent official business',visibility='PUBLIC',structured=True,keep_encrypted_json='[]')))
    elif op=='resume':args=['owner-resume',cfg,command]
    elif op=='owner-pending':args=['owner-action-pending',cfg,workspace]
    elif op=='owner-read':args=['owner-read',cfg,workspace]
    elif op in ['install-begin','install-continue']:args=['owner-'+op,cfg,workspace,ip if op.endswith('begin')else command]
    elif op in ['owner-submit','member-submit']:
     inp.write_text(json.dumps(dict(action_id=x['action_id'],instance_id=x['instance_id'],body_json=json.dumps(x['body']),exact_input_refs_json=json.dumps(x['exact_input_refs'])if'exact_input_refs'in x else None,command_id=x['command_id'])))
     args=['owner-action-submit',cfg,workspace,ip]if op.startswith('owner-')else['action-submit',cfg,ip]
    elif op in ['owner-status','owner-retry']:args=['owner-action-'+op.split('-')[1],cfg,workspace,command]
    elif op in ['member-status','member-retry']:args=['action-'+op.split('-')[1],cfg,command]
    elif op=='offer':
     inp.write_text(json.dumps(dict(recipient_certificate_json=x['certificate_json'],scopes_json=json.dumps(x['scopes']),message='Adopt exact proposal')));args=['owner-admit-offer',cfg,workspace,ip]
    elif op=='deliver':args=['owner-admit-deliver',cfg,workspace,command]
    elif op=='delivery-resume':args=['owner-admit-retry-delivery',cfg,workspace,command]
    elif op=='consent':args=['consent',cfg,command,'ACCEPT']
    elif op=='receive':args=['receive',cfg,command]
    elif op=='receive-resume':args=['receive-retry',cfg,command]
    elif op=='member-read':args=['read','--origin='+c['origin'],'--state-dir='+c['state_dir'],'--identity='+c['identity_path'],'--workspace='+c['workspace_id'],'--owner-actor='+c['owner_actor_id'],'--owner-key='+c['owner_key_id'],'--allow-loopback-http']
    else:raise AssertionError(op)
    argv=[cli,'secure',*args]
  done=subprocess.run(['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'client',str(ROOT),str(empty),selected_interface,*argv],capture_output=True,text=True,timeout=120)
  out=case/'calls'/f'{n:03d}.stdout';out.write_text(done.stdout);out.chmod(0o600);se=case/'calls'/f'{n:03d}.stderr';se.write_text(done.stderr);se.chmod(0o600);calls.append(dict(op=op,interface=selected_interface,exit_code=done.returncode,stdout_sha256=sha(out),stderr_sha256=sha(se)))
  if expect_error:
   assert done.returncode!=0;return json.loads(done.stderr)
  assert done.returncode==0,dict(interface=interface,op=op,call=n,stderr_file=str(se));return json.loads(done.stdout)
 def counts():
  with sqlite3.connect('file:'+str(kernel/'control.sqlite')+'?mode=ro',uri=True)as db:return db.execute('SELECT count(*) FROM secure_commits').fetchone()[0]
 try:
  select=selectors.DefaultSelector();select.register(server.stdout,selectors.EVENT_READ);assert select.select(60);ready=json.loads(server.stdout.readline());select.close();origin=ready['origin']
  runtime=invoke('runtime',dict(origin=origin,state_dir=guest(case/'runtime'),allow_loopback_http=True));runtime_file=case/'runtime.json';runtime_file.write_text(json.dumps(runtime));runtime_file.chmod(0o600)
  owner=dict(origin=origin,state_dir=guest(case/'owner'),allow_loopback_http=True);recipient=dict(origin=origin,state_dir=guest(case/'recipient'),allow_loopback_http=True)
  p=invoke('prepare',owner);assert p['status']=='PENDING';created=invoke('resume',owner,command=p['command_id']);assert created['status']=='CREATED';workspace=created['workspace_id'];who=invoke('identity',owner);actor,key=who['actor_id'],who['key_id']
  initial=invoke('owner-read',owner,workspace=workspace);selected=next(o for o in initial['objects']if o['kind']=='instances'and o['value']['origin_entrypoint']=='wiki');instance=selected['id'];protocol_digest=selected['value']['protocol_digest']
  local=invoke('recipient-create',recipient);assert local['status']=='LOCAL'and local['actor_id']!=actor
  pub=invoke('recipient-publish',recipient);assert pub['status']=='PUBLISHED'
  cert=invoke('lookup',owner,dict(actor_id=local['actor_id'],key_id=local['signing_key_id']));assert cert['actor_id']==local['actor_id']and cert['signing_key_id']==local['signing_key_id']
  scopes=[dict(instance_id=instance,actions=['wiki.create'],protocol_roles=['EDITOR'],capabilities=['EDIT'],expires_at=None)]
  offer=invoke('offer',owner,dict(certificate_json=cert['certificate_json'],scopes=scopes),workspace);assert offer['status']=='PENDING'
  recipient.update(workspace_id=workspace,owner_actor_id=actor,owner_key_id=key)
  consent=invoke('consent',recipient,command=offer['invite_id']);assert consent['status']=='PENDING'
  delivery=invoke('deliver',owner,workspace=workspace,command=offer['invite_id'])
  if delivery['status']=='PENDING':delivery=invoke('delivery-resume',owner,workspace=workspace,command=delivery['grant_id'])
  assert delivery['status']=='AUTHORIZED'
  received=invoke('receive',recipient,command=offer['invite_id'])
  if received['status']=='PENDING':received=invoke('receive-resume',recipient,command=offer['invite_id'])
  assert received['status']=='READY'
  member=dict(recipient,state_dir=guest(case/'member-profile'),identity_path=recipient['state_dir']+'/identity.state')
  def hook(path):
   req=urllib.request.Request(origin.rstrip('/')+path,data=b'{}',method='POST')
   with urllib.request.urlopen(req,timeout=5)as response:return json.load(response)
  def status(path):
   with urllib.request.urlopen(origin.rstrip('/')+path,timeout=5)as response:return json.load(response)
  assert counts()==2
  hook('/__test/ack-arm')
  acknowledged=dict(action_id='wiki.create',instance_id=instance,body=dict(title='Acknowledged unverified',body='POST reply received before signed read refused'),command_id='a'*43)
  returned=invoke('owner-submit',owner,acknowledged,workspace);assert returned['status']=='PENDING'and returned['command_id']=='a'*43
  ack=status('/__test/ack-status');assert ack['finished']and ack['fault']and ack['tampered']==0 and counts()==3
  discovered=invoke('owner-pending',owner,workspace=workspace);assert len(discovered)==1 and discovered[0]['command_id']=='a'*43
  refusal=invoke('owner-status',owner,workspace=workspace,command='a'*43,expect_error=True);assert refusal['code']=='VERIFICATION_FAILED',refusal
  ack=status('/__test/ack-status');assert ack['tampered']>=1
  assert invoke('owner-pending',owner,workspace=workspace)==discovered and counts()==3
  hook('/__test/ack-clear')
  recovered=invoke('owner-status',owner,workspace=workspace,command='a'*43);assert recovered['status']=='ACCEPTED'and recovered['sequence']==3 and recovered['receipt']['actor_id']==actor
  acknowledged_read=invoke('owner-read',owner,workspace=workspace);record=recovered['receipt']['effects'][0]['record_id'];assert any(o['kind']=='records'and o['id']==record and o['value']['payload']['title']=='Acknowledged unverified'for o in acknowledged_read['objects'])
  assert invoke('owner-retry',owner,workspace=workspace,command='a'*43)==recovered and counts()==3
  # Generated operation ID must not reach the killed caller. No native state
  # file is read; recover it only through the public pending interface.
  hook('/__test/delay-next-post')
  config_file=case/'kill-config.json';config_file.write_text(json.dumps(owner));config_file.chmod(0o600)
  input_file=case/'kill-input.json';input_file.write_text(json.dumps(dict(action_id='wiki.create',instance_id=instance,body_json=json.dumps(dict(title='Killed caller record',body='Generated ID recovered publicly')))));input_file.chmod(0o600)
  stdout=case/'kill.stdout';stderr=case/'kill.stderr';stdout.touch(mode=0o600);stderr.touch(mode=0o600)
  with stdout.open('wb')as out,stderr.open('wb')as error:
   child=subprocess.Popen(['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'client',str(ROOT),str(empty),'cli',GSDK+'/target/release/peerwork','secure','owner-action-submit',guest(config_file),workspace,guest(input_file)],stdout=out,stderr=error,start_new_session=True)
   deadline=time.monotonic()+10
   while not status('/__test/post-delay-status')['started']:
    assert child.poll()is None and time.monotonic()<deadline;time.sleep(.02)
   assert child.poll()is None and stdout.stat().st_size==0 and counts()==4
   beforekill=dict(pid=child.pid,process_group=os.getpgid(child.pid),service_applied=True,caller_live=True,stdout_bytes=0,commits=4)
   os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=10)
  assert child.returncode==-9 and stdout.stat().st_size==0
  killproof=dict(before=beforekill,exit_code=child.returncode,stdout_bytes=stdout.stat().st_size,stderr_sha256=sha(stderr));(case/'kill-process.json').write_text(json.dumps(killproof));(case/'kill-process.json').chmod(0o600)
  pending=invoke('owner-pending',owner,workspace=workspace);assert len(pending)==1;original=pending[0]['command_id'];assert original!='a'*43 and pending[0]['actor_id']==actor and pending[0]['workspace_id']==workspace
  with sqlite3.connect('file:'+str(kernel/'control.sqlite')+'?mode=ro',uri=True)as db:applied=db.execute('SELECT command_id,commit_hash FROM secure_commits WHERE sequence=4').fetchone()
  assert applied==(original,pending[0]['commit_hash'])
  unrelated=dict(action_id='wiki.create',instance_id=instance,body=dict(title='Independent unrelated writer',body='Different admitted actor and protected store'),command_id='w'*43)
  assert invoke('member-submit',member,unrelated)['status']=='PENDING';writer=invoke('member-status',member,command='w'*43);assert writer['status']=='ACCEPTED'and writer['sequence']==5 and writer['receipt']['actor_id']==local['actor_id']and counts()==5
  reconciled=invoke('owner-status',owner,workspace=workspace,command=original);assert reconciled['status']=='ACCEPTED'and reconciled['sequence']==4 and reconciled['commit_hash']==pending[0]['commit_hash']and reconciled['receipt']['actor_id']==actor
  assert invoke('owner-pending',owner,workspace=workspace)==[]
  latest=invoke('owner-read',owner,workspace=workspace);assert latest['sequence']==5 and latest['head']==writer['commit_hash']and latest['structure_status']=='ACTIVE'
  for value,title,author in [(reconciled,'Killed caller record',actor),(writer,'Independent unrelated writer',local['actor_id'])]:
   receipt=value['receipt'];assert receipt['workspace_id']==workspace if 'workspace_id'in receipt else value['workspace_id']==workspace
   assert receipt['command_id']==value['command_id']and receipt['instance_id']==instance and receipt['action_id']=='wiki.create'
   rid=receipt['effects'][0]['record_id'];assert any(o['kind']=='records'and o['id']==rid and o['value']['payload']['title']==title and o['value']['payload']['author']==author for o in latest['objects'])
  assert invoke('owner-retry',owner,workspace=workspace,command=original)==reconciled and counts()==5 and invoke('owner-read',owner,workspace=workspace)['head']==latest['head']
  with sqlite3.connect('file:'+str(kernel/'control.sqlite')+'?mode=ro',uri=True)as db:assert db.execute('SELECT count(*) FROM secure_commits WHERE command_id=?',(original,)).fetchone()[0]==1
  events=[json.loads(line)for line in(case/'ack-events.jsonl').read_text().splitlines()];ack_event=next(e for e in events if e['event']=='post_ack_response_finished');assert ack_event['status']in[200,201]and ack_event['command_id']=='a'*43 and ack_event['request_sha256']==discovered[0]['request_sha256']and ack_event['body_sha256']==sha(case/'ack-response.bin')
  assert any(e['event']=='journal_tampered'and e['status']==200 and e['original_sha256']!=e['delivered_sha256']for e in events)
  from urllib.parse import urlsplit
  requests=[json.loads(line)for line in requestlog.read_text().splitlines()];outer=[r for r in requests if r['host']==urlsplit(origin).netloc]
  for command,request_sha in [('a'*43,discovered[0]['request_sha256']),(original,pending[0]['request_sha256'])]:
   exact=[r for r in outer if r['command_id']==command];assert len(exact)==1 and exact[0]['body_sha256']==request_sha
  assert any(o['kind']=='instances'and o['id']==instance and o['value']['protocol_digest']==protocol_digest for o in latest['objects'])
  result=dict(result='PASS',source=SOURCE,classification='operator_synthetic',interface='cli',workspace_id=workspace,instance_id=instance,protocol_digest=protocol_digest,owner_actor=actor,writer_actor=local['actor_id'],acknowledged_command='a'*43,acknowledged_unverified_code=refusal['code'],acknowledged_response_finished=ack['finished'],killed_discovered_command=original,killed_original_sequence=4,unrelated_writer_sequence=5,final_sequence=5,final_head=latest['head'],generated_id_caller_stdout_bytes=0,killed_exit_code=-9,exact_once=True);results.append(result);print(json.dumps(result),flush=True)
 finally:
  server.terminate()
  try:server.wait(timeout=10)
  except subprocess.TimeoutExpired:server.kill();server.wait(timeout=10)
  errstream.close();p=kernel/'exit.json';p.write_text(json.dumps(dict(exit_code=server.returncode,stderr_sha256=sha(err))));p.chmod(0o600)
  p=case/'calls.json';p.write_text(json.dumps(calls,indent=2));p.chmod(0o600);guard()
p=state/'summary.json';p.write_text(json.dumps(results,indent=2));p.chmod(0o600);assert len(results)==1
