"""Three finite residual source boundaries through installed public Python APIs."""
from pathlib import Path
from urllib.parse import urlsplit
import os,json,hashlib,sqlite3,shutil
import peerwork
SOURCE=Path(os.environ['PEERWORK_TEST_SDK_ROOT']);STATE=Path(os.environ['PEERWORK_TEST_STATE']);assert Path(peerwork.__file__).is_relative_to(SOURCE/'dist/python-consumer')
f=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text());i=f['sources'][0];mode=i['mode'];origin=f['origin'];workspace=i['workspace_id'];instance=i['instance_id'];initial=i['latest_sequence'];native=STATE/'native'
source=dict(workspace_id=workspace,protected_ts_state_path=i['state_path'],protected_ts_intent_db_path=i['intent_db_path'],protected_owner_pkcs8_path=i['pem_path'],expected_owner_actor_id=i['owner_actor_id'],expected_owner_key_id=i['owner_key_id'])
options=Path(i['options_path']).read_text();material=Path(i['material_path']).read_text();parsed=json.loads(options)
def count():
 with sqlite3.connect('file:'+str(STATE/'kernel/control.sqlite')+'?mode=ro',uri=True)as db:return db.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=?',(workspace,)).fetchone()[0]
def observed():
 return [x for x in map(json.loads,Path(f['request_log']).read_text().splitlines()[f['fixture_request_lines']:]) if x['host']==urlsplit(origin).netloc and x['path'].endswith('/commits')]
def call(op,digest=None,attach=None):
 owner=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
 try:
  if op=='inspect':
   if mode=='combined':v=owner.inspect_pending_direct_install_packet(**source,selected_command_id=i['pending_command_id'],options_json=options,material_json=material)
   else:v=owner.inspect_completed_direct_install(**source,selected_instance_id=instance,options_json=options,material_json=material)
  elif op=='attach':v=owner.attach_completed_direct_install(**source,selected_instance_id=instance,expected_ts_state_digest=digest,options_json=options,material_json=material)
  elif op=='history':v=owner.attachments()
  elif op=='resume':v=owner.resume_attachment(attach)
  elif op=='read':v=owner.read(workspace)
  else:raise AssertionError(op)
  return dict(ok=True,value=v)
 except peerwork.OwnerWorkspaceError as e:return dict(ok=False,code=e.code)
def success(op,**kw):
 r=call(op,**kw);assert r['ok'],{'phase':op,'mode':mode,'code':r.get('code')};return r['value']
assert count()==initial and not observed() and success('history')==[]
r=call('inspect')
if mode in ['combined','temporal-negative']:
 assert r==dict(ok=False,code='SOURCE_UNRESOLVED'),{'mode':mode,'inspection':r}
 assert success('history')==[] and count()==initial and not observed()
 if mode=='temporal-negative':
  omitted_options=options;options=Path(i['options_path']).with_name('original-options.json').read_text()
  positive=call('inspect');assert positive['ok'] and positive['value']['status']=='COMPLETED_IN_SIGNED_REPLAY' and positive['value']['intent_hash']==i['intent_hash'] and positive['value']['end_sequence']==i['completed_sequence'],positive
  options=omitted_options;assert call('inspect')==dict(ok=False,code='SOURCE_UNRESOLVED')
  assert success('history')==[] and count()==initial and not observed()
  assert len(json.loads(material)['closure']['packages'])==3 and 'dependencies' not in parsed and i['dependency_installed_later'] and i['latest_omitted_resolution_matches_original'] and i['original_prefix_resolution_failure']
 print(json.dumps(dict(result='GAP_CONFIRMED' if mode=='combined' else 'PASS_NEGATIVE',mode=mode,classification='operator_synthetic',source_cohort='34287775ac31e2f812c016affd4038df4f1f7346',code=r['code'],initial_commits=initial,final_commits=count(),native_posts=0,source_removed=False,positive_original_options_control=(mode=='temporal-negative'),package_parts=i.get('source_parts'),object_parts=i.get('object_parts'),python_module=peerwork.__file__)),flush=True)
else:
 assert mode in ['implicit-later','object-later'] and 'dependencies' not in parsed
 if mode=='implicit-later':assert len(json.loads(material)['closure']['packages'])==3
 else:assert i['object_source'] and i['source_parts']>1 and parsed['expected_checkpoint']==i['object_source']['source']
 assert r['ok'],r;inv=r['value'];assert inv['status']=='COMPLETED_IN_SIGNED_REPLAY' and inv['end_sequence']==i['completed_sequence'] and inv['begin_command_id']==i['original_begin_command_id'] and inv['begin_commit_hash']==i['original_begin_commit_hash']
 p=success('attach',digest=inv['ts_state_digest']);assert p['status']=='ATTACHED' and p['sequence']==initial and p['pending_direct_install_status']=='ACCEPTED'
 shutil.move(str(STATE/'source'),str(STATE/'source-removed'))
 for key in ['state_path','pem_path','intent_db_path','options_path','material_path']:assert not Path(i[key]).exists()
 assert success('history')==[p] and success('resume',attach=p['attach_id'])==p
 read=success('read');assert read['workspace_id']==workspace and read['sequence']==initial and read['head']==i['latest_head'] and read['structure_status']=='ACTIVE'
 prot=[x for x in read['objects'] if x['kind']=='protocols' and x['id']==i['protocol_digest']];assert len(prot)==1 and prot[0]['value']['manifest']==i['compiler_oracle']['compiled_manifest']
 if mode=='implicit-later':assert prot[0]['value']['composition']==i['composition']
 assert any(x['kind']=='instances' and x['id']==instance and x['value']['protocol_digest']==i['protocol_digest'] for x in read['objects'])
 assert [x for x in read['objects'] if x['kind']=='records' and x['id']==i['later_record']['id']]==[i['later_record']]
 assert success('resume',attach=p['attach_id'])==p and count()==initial and not observed()
 print(json.dumps(dict(result='PASS',mode=mode,classification='operator_synthetic',source_cohort='34287775ac31e2f812c016affd4038df4f1f7346',completed_sequence=i['completed_sequence'],latest_sequence=initial,native_posts=0,source_removed=True,python_module=peerwork.__file__)),flush=True)
