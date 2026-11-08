"""One independently driven installed interface, operator-synthetic real HTTP journey."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlparse

HERE=Path(__file__).resolve().parent
STATE=Path(os.environ['PEERWORK_TEST_STATE'])
SDK_ROOT=Path(os.environ['PEERWORK_TEST_SDK_ROOT'])
NODE=os.environ['PEERWORK_TEST_NODE']
CLI=os.environ['PEERWORK_TEST_CLI']
INTERFACE=os.environ['PEERWORK_TEST_INTERFACE']
assert INTERFACE in ('python','node','cli')
ready=json.loads((STATE/'ready.json').read_text())
fixture=ready['kernel']['public_read']
config=dict(origin=ready['kernel']['origin'],state_dir=str(STATE/'profile'),identity_path=str(STATE/'profile/identity.state'),
 workspace_id=fixture['workspace_id'],owner_actor_id=fixture['actor_id'],owner_key_id=fixture['signing_key'],authority=fixture['authority'],
 required_features=[],allow_loopback_http=True,max_replay_artifact_bytes=64*1024*1024)
config_path=STATE/'profile-config.json';config_path.write_text(json.dumps(config));config_path.chmod(0o600)
owner_config=STATE/'owner-config.json';owner_config.write_text(json.dumps(dict(origin=config['origin'],state_dir=config['state_dir'],allow_loopback_http=True)));owner_config.chmod(0o600)
observations=STATE/'observations.state'
metric_config=STATE/'observations-config.json';metric_config.write_text(json.dumps({'path':str(observations)}));metric_config.chmod(0o600)
if INTERFACE=='python':
 import peerwork
 client=peerwork.SecurePublicPackageInstaller(config['origin'],config['state_dir'],config['identity_path'],config['workspace_id'],
  owner_actor_id=config['owner_actor_id'],owner_key_id=config['owner_key_id'],authority=config['authority'],allow_loopback_http=True)
 actions=peerwork.SecurePublicActionClient(config['origin'],config['state_dir'],config['identity_path'],config['workspace_id'],
  owner_actor_id=config['owner_actor_id'],owner_key_id=config['owner_key_id'],authority=config['authority'],allow_loopback_http=True)
 observer=peerwork.AcquisitionObservations(str(observations))

def run(operation,arg=None):
 arg={} if arg is None else arg
 if INTERFACE=='python':
  if operation=='identity-info':return peerwork.open_identity(config['identity_path'])
  if operation=='identity-import':return peerwork.import_legacy_owner_identity(arg['config_file'],arg['pem_file'])
  if operation=='read':return actions.read()
  if operation.startswith('catalog-') and operation in ('catalog-search','catalog-inspect'):
   catalog=peerwork.PublicCatalogClient(arg['origin'],allow_loopback_http=True)
   return catalog.search('proposal') if operation=='catalog-search' else catalog.inspect_exact(arg['digest'])
  if operation=='install-begin':return client.begin(**arg)
  if operation=='install-continue':return client.continue_install(arg['command_id'])
  if operation=='install-pending':return client.pending()
  if operation=='action-submit':return actions.submit('proposal.propose',arg['instance_id'],arg['body'],command_id=arg['command_id'])
  if operation=='action-status':return actions.reconcile(arg['command_id'])
  if operation=='action-retry':return actions.retry_saved(arg['command_id'])
  if operation=='append':return observer.append(arg)
  if operation=='catalog-result':return observer.record_catalog_result(arg['event'],arg['result'])
  if operation=='install-result':return observer.record_install_result(arg)
  if operation=='action-result':return observer.record_action_result(arg['event'],arg['selected_instance_id'],arg['result_instance_id'],arg['result'])
  if operation=='export':return observer.export()
  if operation=='scorecard':return observer.scorecard(from_ms=arg['from'],to_exclusive=arg['to_exclusive'],as_of=arg['as_of'])
  if operation=='snapshots':return observer.snapshots()
  raise AssertionError('unsupported Python fixture operation')
 input_file=STATE/'client-input.json'
 input_file.write_text(json.dumps(dict(config=config,arg=arg,observationsPath=str(observations))));input_file.chmod(0o600)
 if INTERFACE=='node':
  completed=subprocess.run([NODE,str(HERE/'interface.cjs'),operation,str(input_file)],capture_output=True,text=True,timeout=90)
  value=json.loads(completed.stdout)
  if completed.returncode:raise RuntimeError(value['code'])
  return value['value']
 metric=operation in ('append','catalog-result','install-result','action-result','export','scorecard','snapshots')
 if metric:
  if operation=='catalog-result':
   r=arg['result'];arg=dict(event=arg['event'],catalog_origin=r['catalog_origin'],bundle_digest=r['bundle_digest'],bundle_canonical_json=r['bundle_canonical_json'])
  if operation=='action-result':
   r=arg['result'];arg=dict(event=arg['event'],selected_instance_id=arg['selected_instance_id'],result_instance_id=arg['result_instance_id'],
    result_status=r['status'],result_command_id=r['command_id'],result_commit_hash=r['commit_hash'],result_sequence=r['sequence'])
  args=[CLI,'observations',operation,str(metric_config)]
  if operation not in ('export','snapshots'):input_file.write_text(json.dumps(arg));args.append(str(input_file))
 elif operation=='identity-info':args=[CLI,'identity','info',config['identity_path']]
 elif operation=='identity-import':args=[CLI,'identity','import-legacy-owner-pem',arg['config_file'],arg['pem_file']]
 elif operation=='read':
  args=[CLI,'secure','read',f'--origin={config["origin"]}',f'--state-dir={config["state_dir"]}',f'--identity={config["identity_path"]}',
   f'--workspace={config["workspace_id"]}',f'--owner-actor={config["owner_actor_id"]}',f'--owner-key={config["owner_key_id"]}',f'--authority={config["authority"]}','--allow-loopback-http']
 elif operation.startswith('catalog-'):
  catalog_config=STATE/'catalog-config.json';catalog_config.write_text(json.dumps(dict(origin=arg['origin'],allow_loopback_http=True)))
  args=[CLI,'secure',operation,str(catalog_config),'proposal' if operation=='catalog-search' else arg['digest']]
 elif operation in ('install-begin','action-submit'):
  if operation=='action-submit':arg=dict(action_id='proposal.propose',instance_id=arg['instance_id'],body_json=json.dumps(arg['body']),command_id=arg['command_id'])
  input_file.write_text(json.dumps(arg));args=[CLI,'secure',operation,str(config_path),str(input_file)]
 else:args=[CLI,'secure',operation,str(config_path)]+([arg['command_id']] if 'command_id' in arg else [])
 completed=subprocess.run(args,capture_output=True,text=True,timeout=90)
 wire=completed.stdout if metric or completed.returncode==0 else completed.stderr
 value=json.loads(wire)
 if completed.returncode:raise RuntimeError(value.get('code','FIXTURE_CLIENT_FAILED'))
 return value['value'] if metric else value

def counts():
 with urllib.request.urlopen(config['origin'].rstrip('/')+'/__test/secure-counts',timeout=5) as r:return json.load(r)
def posts():return [row for line in (STATE/'requests.jsonl').read_text().splitlines() if (row:=json.loads(line))['host']==urlparse(config['origin']).netloc]
def install_posts():return [r for r in posts() if r.get('action_id','').startswith('secure.structure.')]
def ref(kind,n):return f'obs:{kind}:{n:032x}'
def evidence(label,value):
 data=json.dumps(value,sort_keys=True,separators=(',',':')).encode();p=STATE/(label+'.json');p.write_bytes(data);p.chmod(0o600)
 return dict(status='checked',reference='obs:evidence:'+hashlib.sha256(data).hexdigest()[:32])
next_event=0
start_ms=int(time.time()*1000)
def event(task,kind,**known):
 global next_event
 next_event+=1
 value=dict(event_id=ref('event',next_event),occurred_at=int(time.time()*1000),environment='local_test',audience_class='operator_synthetic',
  principal_ref=ref('principal',1),principal_binding={'status':'unknown','reference':None},newness='unknown',newness_evidence={'status':'unknown','reference':None},
  journey_id=ref('journey',task),task_ref=ref('task',task),logical_operation_id=ref('operation',task),attempt_id=ref('attempt',task),
  event_type=kind,outcome='pending',attempt_class='first_attempt',evidence={'status':'claimed','reference':ref('evidence',next_event)},
  observer='installed-http-synthetic',observer_version='1',acceptance_predicate_ref=ref('predicate',1))
 value.update(known);return value

# Missing-info must not create the caller-selected absent identity parent.
try:run('identity-info')
except Exception as error:assert getattr(error,'code',str(error))=='IDENTITY_MISSING'
else:raise AssertionError('missing identity info unexpectedly succeeded')
assert not Path(config['state_dir']).exists()
info=run('identity-import',dict(config_file=str(owner_config),pem_file=str(STATE/'kernel/synthetic-public-read-owner.pem')))
assert info==dict(actor_id=fixture['actor_id'],key_id=fixture['signing_key'])
assert run('read')['sequence']==1
vector=json.loads((SDK_ROOT/'conformance/public-package-vectors.json').read_text())
instance='z'*43
install=dict(closure_json=json.dumps(vector['closure'],separators=(',',':')),expected_package_id='peerwork-proposal-adoption',expected_package_version='1.0.0',
 expected_package_digest=vector['package_digest'],expected_protocol_digest=vector['protocol_digest'],instance_id=instance,entrypoint='proposalAdoption',
 grants_json=json.dumps([dict(actor_id=info['actor_id'],actions=['proposal.propose'],protocol_roles=['AUTHOR'],capabilities=['PROPOSE'],expires_at=None)]))
release=dict(catalog_origin=ready['catalog']['origin']+'/',namespace=None,package_id=install['expected_package_id'],version=install['expected_package_version'],bundle_digest=vector['package_digest'])
# Catalog SDK normalizes the origin, including its trailing slash.
results=[]
for task,branch in [(1,'new_install'),(2,'existing_install')]:
 begun=event(task,'qualified_start');assert run('append',begun)['disposition']=='APPENDED'
 before=counts();before_install_posts=len(install_posts())
 assert run('catalog-search',dict(origin=ready['catalog']['origin']))
 inspected=run('catalog-inspect',dict(origin=ready['catalog']['origin'],digest=vector['package_digest']))
 release['catalog_origin']=inspected['catalog_origin']
 inspected_evidence=evidence(f'task-{task}-catalog',inspected)
 catalog_event=event(task,'release_verified',outcome='pass',release=release,evidence=inspected_evidence)
 run('catalog-result',dict(event=catalog_event,result=inspected))
 selection_event=event(task,'adoption_selected',outcome='pass',release=release,protocol_digest=vector['protocol_digest'],instance_ref=ref('instance',1),
  adoption_branch=branch,association_evidence=evidence(f'task-{task}-selection',install))
 proof=dict(event=selection_event,closure_json=install['closure_json'],bindings_json=None,expected_package_id=install['expected_package_id'],
  expected_package_version=install['expected_package_version'],expected_package_digest=vector['package_digest'],expected_protocol_digest=vector['protocol_digest'],
  selected_instance_id=instance,result_package_digest=None,result_protocol_digest=vector['protocol_digest'],result_instance_id=instance,
  result_status='SELECTED' if task==1 else 'ACTIVE',result_step_action_id=None,result_commit_hash=None)
 if task==2:
  latest=run('read');selected=next(o for o in latest['objects'] if o.get('kind')=='instances' and o.get('id')==instance)
  assert latest['structure_status']=='ACTIVE' and selected['value']['protocol_digest']==vector['protocol_digest']
  selection_event['signed_result_evidence']=evidence('existing-install-signed-read',latest)
 run('install-result',proof)
 if task==1:
  begin=run('install-begin',install)
  assert begin['status']=='PENDING'
  for _ in range(5):
   progress=run('install-continue',dict(command_id=begin['command_id']))
   if progress['status']=='ACCEPTED':break
  assert progress['status']=='ACCEPTED' and progress['step_action_id']=='secure.structure.end'
  assert progress['instance_id']==instance and progress['package_digest']==vector['package_digest'] and progress['protocol_digest']==vector['protocol_digest']
  accepted_event=event(task,'install_accepted',outcome='pass',release=release,protocol_digest=vector['protocol_digest'],instance_ref=ref('instance',1),signed_result_evidence=evidence('install-signed-end',progress))
  accepted=dict(proof,event=accepted_event,result_package_digest=progress['package_digest'],result_protocol_digest=progress['protocol_digest'],
   result_instance_id=progress['instance_id'],result_status=progress['status'],result_step_action_id=progress['step_action_id'],result_commit_hash=progress['commit_hash'])
  run('install-result',accepted)
  assert counts()['commits']==3 and len(install_posts())==2 and run('install-pending')==[]
  before=counts()
 body=dict(title=f'Independent synthetic task {task}',body=f'Reviewable candidate for declared task {task}')
 command=('p' if task==1 else 'q')*43
 run('action-submit',dict(instance_id=instance,body=body,command_id=command))
 outcome=run('action-status',dict(command_id=command))
 assert outcome['status']=='ACCEPTED' and outcome['command_id']==command and outcome['sequence']==before['head_sequence']+1
 receipt=outcome['receipt'];assert receipt['command_id']==command and receipt['sequence']==outcome['sequence'] and receipt['commit_hash']==outcome['commit_hash']
 assert len(receipt['effects'])==1
 latest=run('read');assert latest['sequence']==outcome['sequence']
 record=next(o for o in latest['objects'] if o.get('kind')=='records' and o.get('id')==receipt['effects'][0]['record_id'])
 assert record['value']['schema_ref']=='proposal.candidate' and record['value']['instance_id']==instance
 assert record['value']['payload']==dict(author=info['actor_id'],**body)
 checked=evidence(f'task-{task}-signed-result',dict(receipt=receipt,signed_read=latest,declared_body=body))
 final_event=event(task,'task_outcome_verified',outcome='pass',release=release,protocol_digest=vector['protocol_digest'],instance_ref=ref('instance',1),signed_result_evidence=checked,evidence=checked)
 action_input=dict(event=final_event,selected_instance_id=instance,result_instance_id=record['value']['instance_id'],result=outcome)
 assert run('action-result',action_input)['disposition']=='APPENDED'
 assert run('action-result',action_input)['disposition']=='DUPLICATE'
 previous=len(posts());repeat=run('action-retry',dict(command_id=command));assert repeat==outcome and len(posts())==previous
 assert counts()['commits']==outcome['sequence']
 if task==2:assert len(install_posts())==before_install_posts
 results.append(dict(task=task,branch=branch,sequence=latest['sequence'],install_posts=len(install_posts()),accepted_command_sha256=hashlib.sha256(command.encode()).hexdigest()))
rows=run('export');assert all(r['event']['audience_class']=='operator_synthetic' for r in rows)
encoded=json.dumps(rows)
for forbidden in ['closure_json','bundle_canonical_json',config['workspace_id'],info['actor_id'],instance,'Reviewable candidate for declared task']:
 assert forbidden not in encoded
window=dict(**{'from':start_ms-1},to_exclusive=int(time.time()*1000)+1,as_of=int(time.time()*1000))
score=run('scorecard',window);assert score['scorecard']['excluded_synthetic_seed']==len(rows)
assert all(m['value'] is None for m in score['scorecard']['metrics'])
assert run('scorecard',window)==score and run('snapshots')==[score]
summary=dict(interface=INTERFACE,classification='operator_synthetic',tasks=results,final_sequence=counts()['head_sequence'],observations=len(rows),
 external_metric_values_null=True,business='signed task-specific candidate readback',workflow='scripted public interface; no natural-Agent compliance claim')
(STATE/'result.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
