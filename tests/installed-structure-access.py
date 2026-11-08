# All state is generated for this installed-package acceptance.
import asyncio,json,sys
from pathlib import Path
import peerwork
operation,path=sys.argv[1:];s=json.loads(Path(path).read_text())
identity=peerwork.create_identity(s['identity_path']) if operation=='request' else peerwork.open_identity(s['identity_path'])
profile=Path(path).parent/'context.json'
if operation=='request':
 context=peerwork.bind_structure_context(profile=profile,expected_actor=identity['actor_id'],expected_service='installed-python-access',origin=s['origin'],identity_path=s['identity_path'],journal_path=s['journal_path'],workspace_ids=[s['workspace_id']],allow_loopback_http=True)
 result=asyncio.run(context.request_access_async(s['workspace_id'],{'label':'Installed Python Agent'}));assert result['status']=='waiting'
 print(json.dumps(result['result']))
elif operation=='large-body':
 context=peerwork.bind_structure_context(profile=Path(path).parent/'python-body-context.json',expected_actor=identity['actor_id'],expected_service='installed-python-body',origin=s['origin'],identity_path=s['identity_path'],journal_path=s['journal_path'],workspace_ids=[s['workspace_id']],allow_loopback_http=True)
 selected={'action':'structure.record.get',**s['scope'],'body':{'record_id':s['record_id'],'revision':1}}
 result=asyncio.run(context.execute_structure_intent_async(s['workspace_id'],selected));assert result['status']=='verified' and result['opened_contents'][0]['text']=='\x01'*65536
 result=asyncio.run(context.operate_async(s['workspace_id'],{'kind':'protocol.action','instance_id':s['scope']['instance_id'],'protocol_digest':s['scope']['protocol_digest'],'expected_instance_revision':1,'action_id':'post','values':{},'plaintext_contents':[{'record_index':0,'text':'P'*65536}]},'python-max-body'))
 assert result['status']=='verified'
 print(json.dumps({'state':'PASS','bytes':65536}))
elif operation=='rotate':
 rotation_profile=Path(path).parent/'rotation-context.json'
 context=peerwork.open_context(profile=rotation_profile,expected_actor=identity['actor_id'],expected_service='installed-python-rotation') if rotation_profile.exists() else peerwork.bind_structure_context(profile=rotation_profile,expected_actor=identity['actor_id'],expected_service='installed-python-rotation',origin=s['origin'],identity_path=s['identity_path'],journal_path=s['journal_path'],workspace_ids=[s['workspace_id']],allow_loopback_http=True)
 result=asyncio.run(context.rotate_content_key_async(s['workspace_id'],{'idempotency_key':'python-owner-rotation'}));assert result['status']=='verified'
 kernel=peerwork.KernelClient(origin=s['origin'],journal_path=s['journal_path'],identity_path=s['identity_path'],allow_loopback_http=True)
 same=kernel.rotate_content_key({'workspace_id':s['workspace_id'],'idempotency_key':'python-owner-rotation'});assert same['state']=='COMPLETED' and same['command_id']==result['command_id']
 print(json.dumps({'state':'PASS','epoch':result['result']['content_key_head']['epoch'],'key_id':result['result']['content_key_head']['key_id']}))
else:
 context=peerwork.open_context(profile=profile,expected_actor=identity['actor_id'],expected_service='installed-python-access')
 selected={'owner_id':s['owner_id'],'key_ids':[s['key_id']]}
 result=context.accept_content_keys(s['workspace_id'],selected);assert result['status']=='verified' and result['result']['state']=='IMPORTED'
 # Repeating acceptance through the advanced facade retains the same keys.
 kernel=peerwork.KernelClient(origin=s['origin'],journal_path=s['journal_path'],identity_path=s['identity_path'],allow_loopback_http=True)
 assert kernel.accept_content_keys({'workspace_id':s['workspace_id'],**selected})['state']=='IMPORTED'
 result=context.execute_structure_intent(s['workspace_id'],{'action':'structure.records.read',**s['scope'],'body':{'limit':32}});assert result['status']=='verified'
 opened=result['opened_contents'];assert all(v['state']=='OPENED' for v in opened)
 print(json.dumps({'state':'PASS','opened':len(opened)}))
