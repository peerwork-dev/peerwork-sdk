"""Exact current collection budget and true read timeout; scripted synthetic fixture."""
import hashlib,json,os,subprocess,time,urllib.request
from pathlib import Path
import peerwork,peerwork._peerwork_native as extension
state=Path(os.environ['PEERWORK_TEST_STATE']);f=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text());p=f['public'];interface=f['interface'];bound=f['bound'];sdk=Path(os.environ['PEERWORK_TEST_SDK_ROOT'])
assert Path(peerwork.__file__)==sdk/'dist/python-consumer/peerwork/__init__.py'
assert hashlib.sha256(Path(peerwork.__file__).read_bytes()).hexdigest()=='ed062183121ab295b33532c9150a5d07c3b8123770612b3ede9bad982c772685'
assert hashlib.sha256(Path(extension.__file__).read_bytes()).hexdigest()=='e5fdf5d8ddb39d0b1ea5b08d8ff239ad2875b00617f6a66abe0f349e1a01a232'
identity=state/'identity.state';public=peerwork.open_identity(str(identity)) if f['controls']=='resume-only' else peerwork.import_legacy_identity_pem(str(identity),f['pem']);assert public==dict(actor_id=p['actor_id'],key_id=p['signing_key'])
profile=state/'profile';calls=[]
node=r'''
void(async()=>{const fs=require('fs'),crypto=require('crypto'),x=JSON.parse(fs.readFileSync(0,'utf8')),file=require.resolve(process.env.PEERWORK_TEST_NODE_PACKAGE),addon=process.env.PEERWORK_TEST_NODE_PACKAGE.replace(/agent-sdk$/,'agent-sdk-linux-x64-gnu')+'/index.node';
const hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');if(hash(file)!=='d89711417ffe49db256b25675cfb7c526d7420ac8361c81e260529606de9f7f5'||hash(addon)!=='60697f141fb04c34112e31f375be932f037e591299c21ce636f9cf8087dca792')throw Error('module hash');
try{console.log(JSON.stringify({value:await require(file).readSecureWorkspace(x),module:file,native:addon}));}catch(e){console.log(JSON.stringify({error:{code:e.code,message:e.message}}));}})().catch(e=>{console.error(e);process.exitCode=1;});
'''
def invoke(limit):
 start=time.monotonic()
 if interface=='python':
  try:value=dict(value=peerwork.SecureReadClient(f['origin'],str(profile),str(identity),p['workspace_id'],owner_actor_id=p['actor_id'],owner_key_id=p['signing_key'],allow_loopback_http=True,max_replay_artifact_bytes=limit).read())
  except peerwork.SecureReadError as e:value=dict(error=dict(code=e.code,message=str(e)))
 elif interface=='node':
  options=dict(origin=f['origin'],stateDir=str(profile),identityPath=str(identity),workspaceId=p['workspace_id'],ownerActorId=p['actor_id'],ownerKeyId=p['signing_key'],allowLoopbackHttp=True,maxReplayArtifactBytes=limit)
  run=subprocess.run([os.environ['PEERWORK_TEST_NODE'],'-e',node],input=json.dumps(options),capture_output=True,text=True,timeout=45);assert run.returncode==0,run.stderr;value=json.loads(run.stdout)
 else:
  args=[os.environ['PEERWORK_TEST_CLI'],'secure','read','--origin='+f['origin'],'--state-dir='+str(profile),'--identity='+str(identity),'--workspace='+p['workspace_id'],'--owner-actor='+p['actor_id'],'--owner-key='+p['signing_key'],'--allow-loopback-http','--max-replay-artifact-bytes='+str(limit)]
  run=subprocess.run(args,capture_output=True,text=True,timeout=45)
  value=dict(value=json.loads(run.stdout)) if run.returncode==0 else dict(error=json.loads(run.stderr))
 value['elapsed_seconds']=round(time.monotonic()-start,3);calls.append(dict(limit=limit,**value));(state/('resume-calls.json' if f['controls']=='resume-only' else 'calls.json')).write_text(json.dumps(calls)+'\n');return value
# This file contains only protected public trust metadata; never read identity bytes.
def pointer():
 wire=(profile/'read.profile').read_bytes();magic=b'PEERWORK-NATIVE-SECURE-STATE\n1\n';assert wire.startswith(magic) and len(wire)<16*1024
 raw=json.loads(wire[len(magic):]);return dict(current=raw['current'],floor=raw['floor'])
def post(route):
 with urllib.request.urlopen(urllib.request.Request(f['origin'].rstrip('/')+'/'+route,data=b'',method='POST'),timeout=10) as response:return json.load(response)
def check(value,sequence,head):
 assert value['workspace_id']==p['workspace_id'] and value['sequence']==sequence and value['head']==head and value['structure_status']=='UNSTRUCTURED'
 assert len([o for o in value['objects'] if o['kind']=='records'])==sequence-1
 assert not any(k in value for k in ['jws','private_key','keyring'])
if f['controls']=='resume-only':
 recovered=invoke(bound+1024*1024);check(recovered['value'],53,f['resume_head']);assert pointer()['floor']['sequence']==53
 assert invoke(bound+1024*1024)['value']==recovered['value']
 # Capture after the FINAL successful refresh, not before its generation rotation.
 stable=pointer();assert stable['floor']['sequence']==53
 (state/'pointer-before-timeout.json').write_text(json.dumps(stable,sort_keys=True)+'\n')
 post('__test/delay-next-journal');failed=invoke(bound+1024*1024)
 assert failed['error']['code']=='READ_FAILED' and failed['elapsed_seconds']>=14 and 'value' not in failed
 after=pointer();(state/'pointer-after-timeout.json').write_text(json.dumps(after,sort_keys=True)+'\n');assert after==stable
 time.sleep(max(0,19-failed['elapsed_seconds']))
 assert invoke(bound+1024*1024)['value']==recovered['value']
 (state/'resume-verified-read.json').write_text(json.dumps(recovered['value'])+'\n')
 result=dict(result='PASS',interface=interface,classification='operator_synthetic',same_profile=True,service_restart_same_origin=True,timeout_seconds=failed['elapsed_seconds'],exact_pointer_unchanged=True,final_sequence=53,final_head=f['resume_head'],idempotent=True)
 (state/'resume-effects.json').write_text(json.dumps(result)+'\n');print(json.dumps(result),flush=True)
 raise SystemExit(0)
if f['controls']=='all':
 low=invoke(bound-1);assert low['error']['code']=='RESOURCE_LIMIT';assert pointer()==dict(current=None,floor=None)
high=invoke(bound);check(high['value'],52,p['head']);before=pointer();assert before['floor']['sequence']==52
# Reopening a fresh facade over the same profile reuses persisted transport evidence.
assert invoke(bound)['value']==high['value']
before=pointer()
appended=post('__test/append-public');assert appended['sequence']==53
post('__test/delay-next-journal');timeout=invoke(bound+1024*1024);assert timeout['error']['code']=='READ_FAILED' and timeout['elapsed_seconds']>=14
assert pointer()==before and 'value' not in timeout
assert f['origin'] not in timeout['error']['message']
# Original held response finishes at18s; no new delayed hook is armed.
time.sleep(max(0,19-timeout['elapsed_seconds']))
recovered=invoke(bound+1024*1024);check(recovered['value'],53,appended['head']);assert pointer()['floor']['sequence']==53
assert invoke(bound+1024*1024)['value']==recovered['value']
(state/'verified-read.json').write_text(json.dumps(recovered['value'])+'\n')
result=dict(result='PASS',interface=interface,classification='operator_synthetic',collection_bytes=bound,low_budget=bound-1,resource_error='RESOURCE_LIMIT',first_sequence=52,timeout_error='READ_FAILED',timeout_seconds=timeout['elapsed_seconds'],pointer_unchanged_during_refusal=True,final_sequence=53,final_head=appended['head'],same_profile=True,python_module=str(peerwork.__file__),python_native=str(extension.__file__))
(state/'effects.json').write_text(json.dumps(result)+'\n');print(json.dumps(result),flush=True)
