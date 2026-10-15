"""Compiled-local public Kernel typed-error and unchanged saved-result regression."""
import os,sys,json,subprocess,hashlib,time,threading,http.server,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/'.test-data/t094'; C=OUT/'compiled'
NODE='/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node'
REFERENCE='/root/workdir/message/.worktrees/e2ee-main-integration-20261006'
os.umask(0o077); OUT.mkdir(exist_ok=True); C.mkdir(exist_ok=True)
assert not (C/'peerwork').exists(), 'retain first execution objects'
for src,dst in [(ROOT/'.build-target/debug/peerwork',C/'peerwork'),(ROOT/'.build-target/debug/lib_peerwork_native.so',C/'python/peerwork/_peerwork_native.abi3.so'),(ROOT/'.build-target/debug/libpeerwork_node_native.so',C/'node/node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node')]:
 dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
shutil.copy2(ROOT/'bindings/python/peerwork/__init__.py',C/'python/peerwork/__init__.py')
entry=C/'node/index.cjs';shutil.copy2(ROOT/'bindings/node/index.cjs',entry)
(C/'node/node_modules/@peerwork/agent-sdk-linux-x64-gnu/package.json').write_text('{"main":"index.node"}')
sys.path.insert(0,str(C/'python'));import peerwork
assert Path(peerwork.__file__).resolve()==C/'python/peerwork/__init__.py'
CLI=str(C/'peerwork'); calls=[]
def run(argv,expect=0):
 t=time.monotonic();p=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=40)
 calls.append(dict(argv=list(map(str,argv)),exit=p.returncode,seconds=time.monotonic()-t,stdout=p.stdout,stderr=p.stderr))
 (OUT/'calls.json').write_text(json.dumps(calls,indent=2))
 assert p.returncode==expect,(argv,p.returncode,p.stdout,p.stderr)
 return json.loads(p.stdout if expect==0 else p.stderr)
def shafile(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Failure(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  failures.append(self.path);self.send_response(503);self.end_headers();self.wfile.write(b'SECRET-BODY-DO-NOT-EXPOSE')
 def log_message(self,*args):pass
failures=[];bad=http.server.ThreadingHTTPServer(('127.0.0.1',0),Failure);thread=threading.Thread(target=bad.serve_forever);thread.start()
service=OUT/'reference';service.mkdir(mode=0o700)
env=os.environ.copy();env.update(PEERWORK_REFERENCE_ROOT=REFERENCE,PEERWORK_TEST_STATE=str(service),PEERWORK_TEST_FIRST_POST_MODE='normal');env.pop('PEERWORK_HTTP_PROXY',None)
# Loopback service is selected explicitly; generic environment proxies are not opted in.
os.environ.pop('PEERWORK_HTTP_PROXY',None)
stderr=(OUT/'service.stderr').open('w');server=subprocess.Popen([NODE,str(ROOT/'tests/reference-kernel-server.mjs')],env=env,stdout=subprocess.PIPE,stderr=stderr,text=True)
results={}
try:
 origin=json.loads(server.stdout.readline())['origin'];assert origin.startswith('http://127.0.0.1:')
 for language in ['python','node','cli']:
  case=OUT/language;case.mkdir(mode=0o700);identity=case/'identity';journal=case/'journal.sqlite'
  info=run([CLI,'identity','create',identity]);identity_before=shafile(identity)
  def invoke(mode,selected=origin,code=None,command=None):
   options=dict(mode=mode,origin=selected,identity=str(identity),journal=str(journal),code=code,command=command)
   if language=='python':
    c=peerwork.KernelClient(selected,str(journal),str(identity),allow_loopback_http=True)
    if mode in ['invalid','service']:
     try:c.open();raise AssertionError('unexpected success')
     except peerwork.KernelError as e:
      assert isinstance(e,RuntimeError) and e.code==code;return dict(code=e.code,message=str(e),kind=type(e).__name__)
    if mode=='shape':
     try:peerwork.KernelClient(selected,str(journal),str(identity),transport=peerwork.TransportOptions(request_timeout_ms=0)).open();raise AssertionError('unexpected success')
     except ValueError:return dict(kind='ValueError')
    opened=c.open();assert opened['actor_id']==info['actor_id']
    p=c.prepare(command);assert p['command_id']==command['command_id'];assert c.status(p['command_id'])==dict(state='PENDING');assert c.pending()==[p]
    result=c.submit_saved(p['command_id']);fresh=peerwork.KernelClient(selected,str(journal),str(identity),allow_loopback_http=True)
    status=fresh.status(p['command_id']);retry=fresh.submit_saved(p['command_id']);assert status==dict(state='ACCEPTED',result=result) and retry==result
    return dict(pending=p,status=status,result=result,retry=retry)
   if language=='node':
    request=case/(mode+'.json');request.write_text(json.dumps(options));return run([NODE,ROOT/'tests/kernel-errors-t094/node.cjs',entry,request])
   base=[CLI,'kernel'];tail=[selected,journal,identity,'--allow-loopback-http']
   if mode in ['invalid','service']:return run(base+['open']+tail,1)
   if mode=='shape':return run(base+['open']+tail+['--request-timeout-ms=0'],1)
   run(base+['open']+tail)
   command_file=case/'command.json';command_file.write_text(json.dumps(command));p=run(base+['prepare',selected,journal,identity,command_file,'--allow-loopback-http'])
   assert p['command_id']==command['command_id'];assert run(base+['status',selected,journal,identity,p['command_id'],'--allow-loopback-http'])==dict(state='PENDING');assert run(base+['pending']+tail)==[p]
   result=run(base+['submit',selected,journal,identity,p['command_id'],'--allow-loopback-http']);status=run(base+['status',selected,journal,identity,p['command_id'],'--allow-loopback-http']);retry=run(base+['submit',selected,journal,identity,p['command_id'],'--allow-loopback-http']);assert retry==result and status==dict(state='ACCEPTED',result=result)
   return dict(pending=p,status=status,result=result,retry=retry)
  invalid=invoke('invalid','https://user:SECRET-PROXY@example.invalid/private?SECRET-BODY','CONFIG_INVALID');assert invalid['code']=='CONFIG_INVALID' and 'SECRET' not in json.dumps(invalid)
  failed=invoke('service',f'http://127.0.0.1:{bad.server_port}/','DISCOVERY_FAILED');assert failed['code']=='DISCOVERY_FAILED' and 'SECRET' not in json.dumps(failed)
  assert not journal.exists(),'failed discovery must not create journal'
  shape=invoke('shape');now=int(time.time()*1000)
  import base64
  command=dict(v=1,audience='reference-kernel',command_id=base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='),actor_id=info['actor_id'],authority=hashlib.sha256(info['actor_id'].encode()).hexdigest(),method='POST',path='/api/workspace/v1/commands',workspace_id=None,instance_id=None,protocol_digest=None,action_id='workspace.create',expected_workspace_revision=None,expected_instance_revision=None,exact_input_refs=[],body=dict(name='T094 '+language,visibility='PUBLIC'),issued_at=now,expires_at=now+60000)
  success=invoke('success',command=command);assert success['result']['command_id']==command['command_id'] and success['result']['workspace_id']
  assert shafile(identity)==identity_before
  results[language]=dict(invalid=invalid,service=failed,shape=shape,success=success,identity_unchanged=True)
 assert len(failures)==3 and all(p=='/api/workspace/v1/discovery' for p in failures)
 import urllib.request
 with urllib.request.urlopen(origin+'__test/counts') as response:counts=json.load(response)
 assert counts['commands']==3,counts
 summary=dict(results=results,failed_discovery_requests=failures,counts=counts,python_module=peerwork.__file__,executables={str(p.relative_to(C)):shafile(p) for p in C.rglob('*') if p.is_file()})
 (OUT/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(dict(status='PASS',interfaces=list(results),commands=counts['commands'])))
finally:
 bad.shutdown();bad.server_close();thread.join();server.terminate();exit=server.wait(timeout=10);stderr.close();(OUT/'shutdown.json').write_text(json.dumps(dict(service_exit=exit,stderr_bytes=(OUT/'service.stderr').stat().st_size)))
