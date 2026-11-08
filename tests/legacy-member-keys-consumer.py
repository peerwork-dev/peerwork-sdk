"""Installed Python consumer; source fixture and service are owned by the parent."""
import asyncio,json,sys
from pathlib import Path
import peerwork
p=Path(sys.argv[1]);v=json.loads(p.read_text());profile=v['profile'];origin=v['origin'];request=v['input']
client=peerwork.SecureRecipientEnrollmentClient(origin,profile,allow_loopback_http=True)
first=client.import_legacy_keys(**request);assert first['status']=='IMPORTED' and first['historical_certificates']==1
assert asyncio.run(client.import_legacy_keys_async(**request))['status']=='ALREADY_IMPORTED'
for ws in v['workspaces'][:1]:
 read=peerwork.SecureReadClient(origin,profile,str(Path(profile)/'identity.state'),ws['id'],owner_actor_id=v['owner_actor'],owner_key_id=v['owner_key'],allow_loopback_http=True).read_private()
 assert any(o.get('value',{}).get('payload',{}).get('title')=='Before migration '+ws['label'] for o in read['objects'])
print(json.dumps({'status':'PASS','historical_certificates':first['historical_certificates']}))
