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
name=sys.argv[1]if len(sys.argv)>1 else'scope-revocation-first';assert name.replace('-','').isalnum();state=ROOT/'work'/name;state.mkdir(mode=0o700)
empty=state/'empty-runtimes';empty.mkdir(mode=0o700)
for file in ['python.py','node.cjs']:shutil.copyfile(HERE.parent/'official-independent'/file,state/file);(state/file).chmod(0o600)
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
for mode in ['applied-unresolved','sent-before-apply']:
 interface='cli';case=state/mode;case.mkdir(mode=0o700);(case/'calls').mkdir(mode=0o700);kernel=case/'kernel';kernel.mkdir(mode=0o700);err=kernel/'stderr.log';err.touch(mode=0o600);errstream=err.open('wb');requestlog=case/'requests.jsonl';requestlog.touch(mode=0o600)
 env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(REFERENCE),PEERWORK_TEST_STATE=str(kernel),PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(requestlog),PEERWORK_TEST_PUBLIC_READ='1')
 server=subprocess.Popen([str(NODE),'--require',str(SDK/'tests/historical-direct-request-observer.cjs'),str(SDK/'tests/reference-kernel-server.mjs')],env=env,stdout=subprocess.PIPE,stderr=errstream,text=True)
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
   elif op=='import-fixture-owner':argv=[cli,'identity','import-legacy-pem',c['identity_path'],x['pem_path']]
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
    elif op=='member-pending':args=['action-pending',cfg]
    elif op in ['member-status','member-retry']:args=['action-'+op.split('-')[1],cfg,command]
    elif op=='offer':
     inp.write_text(json.dumps(dict(recipient_certificate_json=x['certificate_json'],scopes_json=json.dumps(x['scopes']),message='Adopt exact proposal')));args=['admit-offer',cfg,ip]
    elif op=='deliver':args=['admit-deliver',cfg,command]
    elif op=='delivery-resume':args=['admit-retry-delivery',cfg,command]
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
  fixture=ready['public_read'];workspace=fixture['workspace_id'];instance=fixture['instance_id'];actor=fixture['actor_id'];key=fixture['signing_key'];(case/'owner').mkdir(mode=0o700)
  owner=dict(origin=origin,state_dir=guest(case/'owner'),identity_path=guest(case/'owner/identity.state'),workspace_id=workspace,owner_actor_id=actor,owner_key_id=key,authority=fixture['authority'],allow_loopback_http=True)
  recipient=dict(origin=origin,state_dir=guest(case/'recipient'),allow_loopback_http=True)
  imported=invoke('import-fixture-owner',owner,dict(pem_path=guest(kernel/'synthetic-public-read-owner.pem')));assert imported==dict(actor_id=actor,key_id=key)
  local=invoke('recipient-create',recipient);assert local['status']=='LOCAL'and local['actor_id']!=actor
  pub=invoke('recipient-publish',recipient);assert pub['status']=='PUBLISHED'
  cert=invoke('lookup',owner,dict(actor_id=local['actor_id'],key_id=local['signing_key_id']));assert cert['actor_id']==local['actor_id']and cert['signing_key_id']==local['signing_key_id']
  scopes=[dict(instance_id=instance,actions=['discussion.post'],protocol_roles=['CONTRIBUTOR'],capabilities=['POST'],expires_at=None)]
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
  before=invoke('member-read',member);assert before['sequence']==2
  original='p'*43;action=dict(action_id='discussion.post',instance_id=instance,body=dict(message='Original unresolved '+mode),command_id=original)
  if mode=='sent-before-apply':hook('/__test/reject-next-post-before-apply')
  posted=invoke('member-submit',member,action,expect_error=(mode=='sent-before-apply'))
  if mode=='sent-before-apply':assert posted['code']=='SERVER_REJECTED'and counts()==2
  else:assert posted['status']=='PENDING'and counts()==3
  pending=invoke('member-pending',member);assert len(pending)==1 and pending[0]['command_id']==original
  writefloor=counts();request_floor=len(requestlog.read_text().splitlines())
  mutation=subprocess.run([str(NODE),str(HERE/'owner-scopes.mjs'),origin,str(kernel),str(REFERENCE),workspace,local['actor_id']],capture_output=True,text=True,timeout=90)
  (case/'scope-change.stdout').write_text(mutation.stdout);(case/'scope-change.stdout').chmod(0o600);(case/'scope-change.stderr').write_text(mutation.stderr);(case/'scope-change.stderr').chmod(0o600)
  assert mutation.returncode==0,'declared TS Owner scope mutation failed';changed=json.loads(mutation.stdout);assert changed['before_sequence']==writefloor and changed['after_sequence']==writefloor+1 and changed['membership_keys_preserved']and changed['target_scopes']==[]and changed['old_epoch']==changed['new_epoch']==0
  current=invoke('member-read',member);assert current['sequence']==writefloor+1 and current['head']==changed['after_head']and current['policy_hash']==changed['after_policy_hash']
  with sqlite3.connect('file:'+str(kernel/'control.sqlite')+'?mode=ro',uri=True)as db:policy_wire=db.execute('SELECT artifact FROM secure_policies WHERE policy_hash=?',(current['policy_hash'],)).fetchone()[0]
  assert hashlib.sha256(policy_wire.encode()).hexdigest()==current['policy_hash'];policy=json.loads(policy_wire);now=next(m for m in policy['payload']['members']if m['actor_id']==local['actor_id']);assert now['scopes']==[]and now['certificate']['payload']['signing_key']==local['signing_key_id']
  post_change_lines=len(requestlog.read_text().splitlines());count_after=counts()
  reconciled=invoke('member-status',member,command=original)
  if mode=='applied-unresolved':
   assert reconciled['status']=='ACCEPTED'and reconciled['sequence']==3 and reconciled['commit_hash']==pending[0]['commit_hash']and reconciled['receipt']['actor_id']==local['actor_id']
   assert invoke('member-retry',member,command=original)==reconciled and invoke('member-pending',member)==[]
   rid=reconciled['receipt']['effects'][0]['record_id'];assert any(o['kind']=='records'and o['id']==rid and o['value']['payload']['message']==action['body']['message']and o['value']['payload']['author']==local['actor_id']for o in current['objects'])
  else:
   assert reconciled['status']=='PENDING'and reconciled['sequence']is None and reconciled['receipt']is None
   refused=invoke('member-retry',member,command=original,expect_error=True);assert refused['code']=='VERIFICATION_FAILED',refused
   assert invoke('member-pending',member)==pending and not any(o['kind']=='records'and o['value']['payload'].get('message')==action['body']['message']for o in current['objects'])
  new=dict(action_id='discussion.post',instance_id=instance,body=dict(message='Revoked new write must not apply'),command_id='n'*43)
  new_refused=invoke('member-submit',member,new,expect_error=True);assert new_refused['code']=='ACTION_PREPARE_FAILED',new_refused
  final=invoke('member-read',member);assert final==current and counts()==count_after and len(requestlog.read_text().splitlines())==post_change_lines
  from urllib.parse import urlsplit
  requests=[json.loads(line)for line in requestlog.read_text().splitlines()];outer=[r for r in requests if r['host']==urlsplit(origin).netloc and r['command_id']==original];assert len(outer)==1 and outer[0]['body_sha256']==pending[0]['request_sha256']
  with sqlite3.connect('file:'+str(kernel/'control.sqlite')+'?mode=ro',uri=True)as db:actual=db.execute('SELECT count(*) FROM secure_commits WHERE command_id=?',(original,)).fetchone()[0]
  assert actual==(1 if mode=='applied-unresolved'else 0)
  result=dict(result='PASS',mode=mode,source=SOURCE,classification='operator_synthetic',interface='cli',workspace_id=workspace,member_actor=local['actor_id'],owner_actor=actor,original_command=original,original_request_sha256=pending[0]['request_sha256'],original_commit_hash=pending[0]['commit_hash'],original_applied_count=actual,original_status=reconciled['status'],historical_sequence=reconciled['sequence'],current_sequence=current['sequence'],current_policy_hash=current['policy_hash'],old_policy_hash=changed['before_policy_hash'],current_scopes=[],membership_keys_epoch_preserved=True,new_write_error=new_refused['code'],retry_error=None if mode=='applied-unresolved'else refused['code'],post_revocation_commit_posts=0);results.append(result);print(json.dumps(result),flush=True)
 finally:
  server.terminate()
  try:server.wait(timeout=10)
  except subprocess.TimeoutExpired:server.kill();server.wait(timeout=10)
  errstream.close();p=kernel/'exit.json';p.write_text(json.dumps(dict(exit_code=server.returncode,stderr_sha256=sha(err))));p.chmod(0o600)
  p=case/'calls.json';p.write_text(json.dumps(calls,indent=2));p.chmod(0o600);guard()
p=state/'summary.json';p.write_text(json.dumps(results,indent=2));p.chmod(0o600);assert len(results)==2
