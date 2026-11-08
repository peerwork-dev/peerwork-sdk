"""Cross-language recovery of synthetic native preparation plans."""
import asyncio,json,sys
from pathlib import Path
import peerwork
operation,source=sys.argv[1:]
s=json.loads(Path(source).read_text())
k=peerwork.KernelClient(origin=s['origin'],journal_path=s['journal_path'],identity_path=s['identity_path'],allow_loopback_http=True)
async def run():
 if operation=='page':
  p=await k.pending_page_async(limit=32)
  assert any(i['command_id']==s['command_id'] and i['phase']=='PREPARATION' for i in p['preparations']['items'])
  return {'state':'PASS','found_preparation':True}
 r=await k.resume_structure_intent_async(s['command_id'])
 assert r['state'] in ('ACCEPTED','COMPLETED'),r
 return {'state':r['state'],'command_id':r.get('command_id',r['result']['command_id']),'record_id':(r['result'].get('produced_record_ids') or [None])[0]}
print(json.dumps(asyncio.run(run())))
