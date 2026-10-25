"""Installed wheel history approval/read, using only generated synthetic state."""
import asyncio,json,sys
from pathlib import Path
import peerwork
operation,source=sys.argv[1:];s=json.loads(Path(source).read_text())
k=peerwork.KernelClient(origin=s['origin'],identity_path=s['identity_path'],journal_path=s['journal_path'],allow_loopback_http=True)
async def run():
 if operation=='approve':
  r=await k.authorize_access_async(s['selection']);assert r['state']=='ACCEPTED',r
  assert r['result']['key_history']['state']=='READY',r
  return {'state':'PASS','key_history':r['result']['key_history']}
 r=await k.execute_structure_intent_async({'action':'structure.records.read',**s['scope'],'body':{'limit':32}})
 assert r['state']=='ACCEPTED',r
 opened=r['result']['opened_contents'];assert len(opened)==32 and all(v['state']=='OPENED' for v in opened),r
 return {'state':'PASS','opened':len(opened)}
print(json.dumps(asyncio.run(run())))
