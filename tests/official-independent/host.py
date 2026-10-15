"""Three independent installed official proposal/adoption/task journeys."""
from pathlib import Path
import hashlib,json,os,selectors,sqlite3,subprocess,sys,shutil
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
name=sys.argv[1]if len(sys.argv)>1 else'official-independent-first';assert name.replace('-','').isalnum();state=ROOT/'work'/name;state.mkdir(mode=0o700)
empty=state/'empty-runtimes';empty.mkdir(mode=0o700)
for file in ['python.py','node.cjs']:shutil.copyfile(HERE/file,state/file);(state/file).chmod(0o600)
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
for mode in sys.argv[2:]or['python','node','cli']:
 assert mode in ['python','node','cli','python-cli-handoff'];interface='python'if mode=='python-cli-handoff'else mode;case=state/mode;case.mkdir(mode=0o700);(case/'calls').mkdir(mode=0o700);kernel=case/'kernel';kernel.mkdir(mode=0o700);err=kernel/'stderr.log';err.touch(mode=0o600);errstream=err.open('wb');requestlog=case/'requests.jsonl';requestlog.touch(mode=0o600)
 env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(REFERENCE),PEERWORK_TEST_STATE=str(kernel),PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(requestlog))
 server=subprocess.Popen([str(NODE),'--require',str(SDK/'tests/historical-direct-request-observer.cjs'),str(SDK/'tests/reference-kernel-server.mjs')],env=env,stdout=subprocess.PIPE,stderr=errstream,text=True)
 def guest(p):return'/'+str(p.relative_to(ROOT))
 calls=[]
 def invoke(op,c,input=None,workspace=None,command=None):
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
  assert done.returncode==0,dict(interface=interface,op=op,call=n,stderr_file=str(se));return json.loads(done.stdout)
 def counts():
  with sqlite3.connect('file:'+str(kernel/'control.sqlite')+'?mode=ro',uri=True)as db:return db.execute('SELECT count(*) FROM secure_commits').fetchone()[0]
 try:
  select=selectors.DefaultSelector();select.register(server.stdout,selectors.EVENT_READ);assert select.select(60);ready=json.loads(server.stdout.readline());select.close();origin=ready['origin']
  runtime=invoke('runtime',dict(origin=origin,state_dir=guest(case/'runtime'),allow_loopback_http=True));runtime_file=case/'runtime.json';runtime_file.write_text(json.dumps(runtime));runtime_file.chmod(0o600)
  owner=dict(origin=origin,state_dir=guest(case/'owner'),allow_loopback_http=True);recipient=dict(origin=origin,state_dir=guest(case/'recipient'),allow_loopback_http=True)
  p=invoke('prepare',owner);assert p['status']=='PENDING';created=invoke('resume',owner,command=p['command_id']);assert created['status']=='CREATED';workspace=created['workspace_id'];who=invoke('identity',owner);actor,key=who['actor_id'],who['key_id']
  instance='z'*43;grants=[dict(actor_id=actor,actions=['proposal.proposal.propose','tasks.task.create_from_proposal'],protocol_roles=['proposal.AUTHOR','tasks.MANAGER'],capabilities=['proposal.PROPOSE','tasks.MANAGE'],expires_at=None)]
  selection=dict(closure_json=json.dumps(vector['closure'],separators=(',',':')),expected_package_id='peerwork-tasks-proposal-adoption',expected_package_version='2.0.0',expected_package_digest=vector['root_package_digest'],expected_protocol_digest=vector['protocol_digest'],instance_id=instance,entrypoint='proposalTasks',grants_json=json.dumps(grants))
  begin=invoke('install-begin',owner,selection,workspace);assert begin['status']=='PENDING'and begin['protocol_digest']==vector['protocol_digest']and begin['package_digest']==vector['root_package_digest'];progress=begin
  for _ in range(8):
   if progress['status']=='ACCEPTED':break
   progress=invoke('install-continue',owner,workspace=workspace,command=begin['command_id'])
  assert progress['status']=='ACCEPTED'and progress['protocol_digest']==vector['protocol_digest']
  local=invoke('recipient-create',recipient);assert local['status']=='LOCAL'and local['actor_id']!=actor
  pub=invoke('recipient-publish',recipient);assert pub['status']=='PUBLISHED'
  cert=invoke('lookup',owner,dict(actor_id=local['actor_id'],key_id=local['signing_key_id']));assert cert['actor_id']==local['actor_id']and cert['signing_key_id']==local['signing_key_id']
  scopes=[dict(instance_id=instance,actions=['proposal.proposal.adopt'],protocol_roles=['proposal.ADOPTER'],capabilities=['proposal.ADOPT'],expires_at=None)]
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
  proposal=dict(action_id='proposal.proposal.propose',instance_id=instance,body=dict(title='Independent proposal',body='Exact adoption becomes a traceable task'),command_id='p'*43)
  assert invoke('owner-submit',owner,proposal,workspace)['status']=='PENDING';accepted=invoke('owner-status',owner,workspace=workspace,command=proposal['command_id']);assert accepted['status']=='ACCEPTED'and accepted['receipt']['actor_id']==actor
  candidate=accepted['receipt']['effects'][0]['record_id'];ref=dict(record_id=candidate,revision=1)
  adoption=dict(action_id='proposal.proposal.adopt',instance_id=instance,body=dict(candidate_ref=ref),exact_input_refs=[ref],command_id='a'*43)
  assert invoke('member-submit',member,adoption)['status']=='PENDING';adopted=invoke('member-status',member,command=adoption['command_id']);assert adopted['status']=='ACCEPTED'and adopted['receipt']['actor_id']==local['actor_id']
  ar=invoke('member-read',member);current=max([o for o in ar['objects']if o['kind']=='instances'and o['id']==instance],key=lambda o:o['revision']);assert current['value']['state']['proposal']['adopted']is True and current['value']['state']['proposal']['adopted_ref']==ref
  operation=next(o for o in ar['operations']if o.get('input',{}).get('action_id')=='proposal.proposal.adopt');assert operation['input']['exact_input_refs']==[ref]
  task=dict(action_id='tasks.task.create_from_proposal',instance_id=instance,body=dict(title='Execute independent proposal',description='Implement adopted decision',assignee=local['actor_id'],proposal_ref=ref),exact_input_refs=[ref],command_id='t'*43)
  assert invoke('owner-submit',owner,task,workspace)['status']=='PENDING';accepted_task=invoke('owner-status',owner,workspace=workspace,command=task['command_id']);assert accepted_task['status']=='ACCEPTED'and accepted_task['receipt']['actor_id']==actor
  taskid=accepted_task['receipt']['effects'][0]['record_id'];final=invoke('owner-read',owner,workspace=workspace);assert final['workspace_id']==workspace and final['structure_status']=='ACTIVE'and final['sequence']==accepted_task['sequence']
  candidate_row=next(o for o in final['objects']if o['id']==candidate);assert candidate_row['value']['payload']['title']==proposal['body']['title']and candidate_row['value']['payload']['author']==actor
  tr=next(o for o in final['objects']if o['id']==taskid);assert tr['value']['schema_ref']=='tasks.task.revision'and tr['value']['payload']['title']==task['body']['title']and tr['value']['payload']['author']==actor
  relation=next(o for o in final['objects']if o['kind']=='record_relations'and o['value'].get('record_id')==taskid);assert relation['value']['kind']=='tasks.based_on_candidate'and relation['value']['target_record']==candidate and relation['value']['target_revision']==1
  head=next(o for o in final['objects']if o['kind']=='entity_heads'and o['value'].get('record_id')==taskid);assert head['value']['revision']==1
  before=counts();assert invoke('member-retry',member,command=adoption['command_id'])['status']=='ACCEPTED';assert invoke('owner-retry',owner,workspace=workspace,command=task['command_id'])['status']=='ACCEPTED';after=invoke('owner-read',owner,workspace=workspace);assert counts()==before and after['sequence']==final['sequence']and after['head']==final['head']
  result=dict(result='PASS',interface=mode,source=SOURCE,classification='operator_synthetic',workspace_id=workspace,owner_actor=actor,adopter_actor=local['actor_id'],candidate_ref=ref,task_record_id=taskid,final_sequence=final['sequence'],final_head=final['head'],commits=before,closure_digest=vector['root_package_digest'],protocol_digest=vector['protocol_digest'],runtime_absence='other-language prefixes hidden and actual execution refused in each invocation',call_count=len(calls));results.append(result);print(json.dumps(result),flush=True)
 finally:
  server.terminate()
  try:server.wait(timeout=10)
  except subprocess.TimeoutExpired:server.kill();server.wait(timeout=10)
  errstream.close();p=kernel/'exit.json';p.write_text(json.dumps(dict(exit_code=server.returncode,stderr_sha256=sha(err))));p.chmod(0o600)
  p=case/'calls.json';p.write_text(json.dumps(calls,indent=2));p.chmod(0o600);guard()
p=state/'summary.json';p.write_text(json.dumps(results,indent=2));p.chmod(0o600);assert len(results)==len(sys.argv[2:]or['python','node','cli'])
