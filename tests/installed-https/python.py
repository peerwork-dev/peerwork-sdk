import json,os,sys,time,hashlib,platform
from pathlib import Path
sys.path.insert(0,str(Path(os.environ['HOME'])/'installed'))
import peerwork,peerwork._peerwork_native as native
assert os.geteuid()==65534
x=json.loads(Path(os.environ['HOME'],'input.json').read_text());expected={'items':[],'next':None,'watermark':0};calls=[]
def call(name,origin,transport,query='t090'):
 start=time.monotonic()
 try:
  kw={} if transport is None else {'transport':peerwork.TransportOptions(**transport)}
  v=peerwork.PublicCatalogClient(origin,**kw).search(query);assert json.loads(v['listing_canonical_json'])==expected and v['listing']==expected
  r=dict(ok=True,value=v)
 except peerwork.PublicCatalogError as error:r=dict(ok=False,code=error.code,message=str(error))
 if not r['ok']:assert r['code']=='CATALOG_TRANSPORT_FAILED',r
 r.update(name=name,seconds=time.monotonic()-start,target=origin+'/api/protocol-catalog/v1/packages');calls.append(r);return r
ca=dict(request_timeout_ms=2000,additional_root_pem_files=[x['ca']])
assert not call('default-untrusted',x['origin'],None)['ok']
assert call('explicit-CA',x['origin'],ca)['ok']
assert not call('hostname-mismatch',x['origin'].replace('localhost','127.0.0.1'),ca)['ok']
assert not call('selected-timeout',x['origin'],dict(ca,request_timeout_ms=100),'delay')['ok']
assert call('normal-recovery',x['origin'],ca)['ok']
assert call('OS-store-plus-additional-root',x['os_origin'],ca)['ok']
print(json.dumps(dict(result='PASS',interface='python',uid=os.geteuid(),runtime=sys.version,libc=platform.libc_ver(),calls=calls,loaded=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in [Path(peerwork.__file__),Path(native.__file__)]])))
