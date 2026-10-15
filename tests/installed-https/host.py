"""Three fresh compiler-free runtimes, one public synthetic HTTPS fixture."""
from pathlib import Path
import os,sys,json,hashlib,shutil,subprocess,time,datetime,threading,ssl
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from urllib.parse import urlsplit,parse_qs
W=Path(__file__).resolve().parents[2];HERE=Path(__file__).parent;E=W/'.test-data/t090';E.mkdir(parents=True,exist_ok=True)
MAIN=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012');BASE=MAIN/'.build-artifacts/https-runtime-t090-20261015';PUBLIC=MAIN/'.build-artifacts/clean-gnu-runtime-t084-20261015'
COHORT=MAIN/'.build-artifacts/transport-sdk-t089-20261015';SDK=COHORT/'rootfs/work/sdk-config-t062-20261015';HOME='/home/HTTPS offline 用户';PIN='de384e52782f4e3f9fb6fe0b6a02cd3abe80f73d';SOURCE='8d5014f36469247b01872b2d84d37e9937d148b0f26647a4e05cdce08d035368'
ARTIFACT=os.environ.get('PEERWORK_T090_ARTIFACT_MANIFEST_SHA256');FORBIDDEN={'rustc','rustdoc','cargo','cc','gcc','g++','c++','clang','clang++','ld','ld.lld','lld','as','make','cmake','ninja','pkg-config','docker','dockerd','node-gyp','node-gyp.js'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n');p.chmod(0o600)
def inventory(root,label):
 files=[p for p in root.rglob('*') if p.is_file()]
 assert not[p for p in files if p.name in FORBIDDEN or p.suffix in {'.h','.hpp','.a'}]
 if label!='python':assert not[p for p in files if p.name.startswith(('python','libpython'))]
 if label!='node':assert not[p for p in files if p.name in {'node','npm','npm-cli.js'}]
 if label!='cli':assert not[p for p in files if p.name=='peerwork' and p.stat().st_mode&0o111]
 assert not(root/'usr/include').exists()
 return dict(files=len(files),bytes=sum(p.stat().st_size for p in files),inventory=[dict(path=str(p.relative_to(root)),sha256=sha(p),size=p.stat().st_size)for p in files],physical_absence=True)
def chroot(root,argv):
 return ['/usr/sbin/chroot','--userspec=65534:65534',str(root),*argv]
ENV=dict(HOME=HOME,PATH='/usr/bin',PYTHONHOME='/usr',PYTHONDONTWRITEBYTECODE='1',PIP_DISABLE_PIP_VERSION_CHECK='1')
def run(label,phase,root,argv,expected=0):
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic();command=chroot(root,argv);r=subprocess.run(command,env=ENV,capture_output=True,text=True,timeout=90)
 record=dict(phase=phase,argv=command,exit_code=r.returncode,started=start,seconds=time.monotonic()-t,stdout=r.stdout,stderr=r.stderr);dump(E/(label+'-'+phase+'.json'),record)
 if expected is not None:assert r.returncode==expected,(label,phase,r.stderr)
 return r

def prepare():
 if BASE.exists():assert '--resume-preparation' in sys.argv
 else:BASE.mkdir(mode=0o755)
 BASE.chmod(0o755)
 for label in ['python','node','cli']:
  root=BASE/label;existed=root.exists()
  if existed:assert '--resume-preparation' in sys.argv
  else:root.mkdir(mode=0o755)
  root.chmod(0o755)
  # Explicit whitelist: no old /home, /work, /packages, keys, profiles or SDK install.
  for name in ([] if existed else ['usr','lib64']):
   shutil.copytree(PUBLIC/label/name,root/name,ignore=shutil.ignore_patterns('peerwork') if label=='cli' else None)
  for name in ['home','etc','packages']:(root/name).mkdir(mode=0o755,exist_ok=True)
  (root/'tmp').mkdir(mode=0o1777,exist_ok=True);(root/'tmp').chmod(0o1777)
  home=root/HOME.lstrip('/');home.mkdir(mode=0o700,exist_ok=True);assert not list(home.iterdir());home.chmod(0o700);os.chown(home,65534,65534)
  (root/'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n');(root/'etc/nsswitch.conf').write_text('hosts: files\npasswd: files\ngroup: files\n');(root/'etc/passwd').write_text('nobody:x:65534:65534:synthetic:'+HOME+':/usr/bin/false\n');(root/'etc/group').write_text('nogroup:x:65534:\n')
  for p in (root/'etc').iterdir():p.chmod(0o644)
  for directory in root.rglob('*'):
   if directory.is_dir() and directory!=home and not directory.is_relative_to(home):directory.chmod(0o1777 if directory==root/'tmp' else 0o755)
  dump(E/(label+'-runtime-before.json'),inventory(root,label))
  run(label,'loader-preflight',root,['/lib64/ld-linux-x86-64.so.2','--version'])
  if label=='python':run(label,'installer-preflight',root,['/usr/bin/python3','-m','pip','--version'])
  if label=='node':run(label,'installer-preflight',root,['/usr/bin/node','/usr/lib/npm/bin/npm-cli.js','--version'])
 # Fresh preparation includes the final qualified permissions AND dynamic DNS closure.
 subprocess.run([sys.executable,str(HERE/'qualify.py')],check=True)
 subprocess.run([sys.executable,str(HERE/'dns.py')],check=True)
 dump(E/'prepared.json',dict(result='PASS',public_whitelist=['/usr','/lib64'],root=str(BASE),ready=datetime.datetime.now(datetime.timezone.utc).isoformat()))

def guard():
 assert ARTIFACT and len(ARTIFACT)==64
 assert sha(COHORT/'source-manifest-final.sha256')==SOURCE and sha(COHORT/'artifact-manifest.sha256')==ARTIFACT
 assert json.loads((COHORT/'cohort-source.json').read_text())['source_commit']==PIN
 assert json.loads((COHORT/'cohort-source.json').read_text())['source_files']==813
 for p in ['build.terminal.json','install.terminal.json','verify.terminal.json']:assert json.loads((COHORT/p).read_text())['exit_code']==0
 rows=[]
 for line in (COHORT/'artifact-manifest.sha256').read_text().splitlines():
  h,rel=line.split(None,1);p=COHORT/rel.lstrip('*');assert sha(p)==h;rows.append(dict(path=str(p),sha256=h,size=p.stat().st_size))
 assert len(rows)==14;return rows

def put(src,dest):dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest);dest.chmod(0o644)
def install(label):
 root=BASE/label;home=root/HOME.lstrip('/')
 if label=='python':
  name='peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl';put(SDK/'dist/wheels'/name,root/'packages'/name)
  run(label,'offline-install',root,['/usr/bin/python3','-m','pip','install','--no-index','--no-deps','--target',HOME+'/installed','/packages/'+name])
  put(HERE/'python.py',home/'consumer.py');os.chown(home/'consumer.py',65534,65534)
  run(label,'loaded-preflight',root,['/usr/bin/python3','-c',"import os,sys,json;sys.path.insert(0,"+repr(HOME+'/installed')+");import peerwork,peerwork._peerwork_native as n;assert os.geteuid()==65534;print(json.dumps({'wrapper':peerwork.__file__,'native':n.__file__,'runtime':sys.version}))"])
 elif label=='node':
  for name in ['peerwork-agent-sdk-0.0.1.tgz','peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz']:put(SDK/'dist/npm'/name,root/'packages'/name)
  (home/'package.json').write_text('{"private":true,"name":"https-t090"}');os.chown(home/'package.json',65534,65534)
  run(label,'offline-install',root,['/usr/bin/node','/usr/lib/npm/bin/npm-cli.js','install','--prefix',HOME,'--cache',HOME+'/npm-cache','--offline','--ignore-scripts','--no-audit','--no-fund','--no-save','/packages/peerwork-agent-sdk-0.0.1.tgz','/packages/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz'])
  put(HERE/'node.cjs',home/'consumer.cjs');os.chown(home/'consumer.cjs',65534,65534)
  run(label,'loaded-preflight',root,['/usr/bin/node','-e',"if(process.geteuid()!==65534)throw Error('UID');const s=require(process.env.HOME+'/node_modules/@peerwork/agent-sdk');console.log(JSON.stringify({version:s.version(),runtime:process.version,wrapper:require.resolve(process.env.HOME+'/node_modules/@peerwork/agent-sdk'),native:Object.keys(require.cache).find(p=>p.endsWith('.node'))}))"])
 else:
  put(SDK/'target/release/peerwork',root/'usr/bin/peerwork');(root/'usr/bin/peerwork').chmod(0o755)
  run(label,'loaded-preflight',root,['/usr/bin/peerwork','version'])
 dump(E/(label+'-runtime-installed.json'),inventory(root,label))

def tls_fixture():
 leaf=E/'tls-runtime';resume='--resume-same-fixture' in sys.argv
 saved=json.loads((BASE/'python'/HOME.lstrip('/')/'input.json').read_text()) if resume else None
 if resume:assert leaf.is_dir()
 else:leaf.mkdir(mode=0o700)
 for ca in ([] if resume else ['ca1','ca2']):
  subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',ca+'.key','-out',ca+'.pem','-days','1','-subj','/CN=synthetic '+ca],cwd=leaf,check=True,capture_output=True)
  subprocess.run(['/usr/bin/openssl','req','-newkey','rsa:2048','-nodes','-keyout',ca+'-server.key','-out',ca+'-server.csr','-subj','/CN=localhost'],cwd=leaf,check=True,capture_output=True)
  (leaf/'extension.cnf').write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
  subprocess.run(['/usr/bin/openssl','x509','-req','-in',ca+'-server.csr','-CA',ca+'.pem','-CAkey',ca+'.key','-CAcreateserial','-out',ca+'-server.pem','-days','1','-extfile','extension.cnf'],cwd=leaf,check=True,capture_output=True)
 for p in leaf.iterdir():p.chmod(0o600)
 requests=[];servers=[];threads=[]
 for ca in ['ca1','ca2']:
  def handler(authority):
   class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
     path=urlsplit(self.path);query=parse_qs(path.query);row=dict(authority=authority,method='GET',target=self.path,status=200);requests.append(row)
     assert path.path=='/api/protocol-catalog/v1/packages' and query['limit']==['20']
     if query['q']==['delay']:time.sleep(.4)
     body=b'{"items":[],"next":null,"watermark":0}';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
     try:self.wfile.write(body)
     except (BrokenPipeError,ssl.SSLError):pass
    def do_POST(self):requests.append(dict(authority=authority,method='POST',target=self.path,status=405));self.send_error(405)
   return Handler
  port=int(urlsplit(saved['origin' if ca=='ca1' else 'os_origin']).port) if resume else 0
  server=ThreadingHTTPServer(('127.0.0.1',port),handler(ca));context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(leaf/(ca+'-server.pem'),leaf/(ca+'-server.key'));server.socket=context.wrap_socket(server.socket,server_side=True);t=threading.Thread(target=server.serve_forever);t.start();servers.append(server);threads.append(t)
 dump(E/'fixture.json',dict(origin='https://localhost:'+str(servers[0].server_port),os_origin='https://localhost:'+str(servers[1].server_port),public_certificates={p.name:sha(p) for p in leaf.glob('*.pem')},same_saved_fixture=resume))
 return leaf,requests,servers,threads

def execute():
 before=guard();dump(E/'cohort-before.json',before)
 assert (E/'prepared.json').exists()
 assert json.loads((E/'dns-qualified.json').read_text())['result']=='PASS'
 qualification=json.loads((E/'qualification.json').read_text());assert qualification['result']=='PASS' and len(qualification['calls'])==3 and all(x['exit_code']==0 for x in qualification['calls'])
 # Gate source syntax/parse before installers, then all loaded-runtime preflights before first SDK HTTPS call.
 for p in [HERE/'host.py',HERE/'python.py']:compile(p.read_text(),str(p),'exec')
 subprocess.run(['/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node','--check',str(HERE/'node.cjs')],check=True)
 if '--resume-same-fixture' in sys.argv:
  dns=json.loads((E/'dns-qualified.json').read_text());assert dns['result']=='PASS' and len(dns['calls'])==3
  for label in ['python','node','cli']:
   assert json.loads((E/(label+'-loaded-preflight.json')).read_text())['exit_code']==0
   assert not(BASE/label/'usr/bin/getent').exists()
   dump(E/(label+'-runtime-resumed.json'),inventory(BASE/label,label))
 else:
  for label in ['python','node','cli']:install(label)
 leaf,requests,servers,threads=tls_fixture();origin='https://localhost:'+str(servers[0].server_port);os_origin='https://localhost:'+str(servers[1].server_port);results=[]
 try:
  for label in ['python','node','cli']:
   root=BASE/label;home=root/HOME.lstrip('/')
   for rel in ['etc/ssl/certs/ca-certificates.crt','etc/pki/tls/certs/ca-bundle.crt','etc/ssl/cert.pem']:put(leaf/'ca2.pem',root/rel)
   for directory in (root/'etc').rglob('*'):
    if directory.is_dir():directory.chmod(0o755)
   put(leaf/'ca1.pem',home/'ca1.pem');dump(home/'input.json',dict(origin=origin,os_origin=os_origin,ca=HOME+'/ca1.pem'));os.chown(home/'input.json',65534,65534)
   if label=='python':r=run(label,'HTTPS',root,['/usr/bin/python3',HOME+'/consumer.py']);result=json.loads(r.stdout)
   elif label=='node':r=run(label,'HTTPS',root,['/usr/bin/node',HOME+'/consumer.cjs']);result=json.loads(r.stdout)
   else:
    calls=[]
    for name,target,transport,query,code in [('default-untrusted',origin,None,'t090',1),('explicit-CA',origin,dict(request_timeout_ms=2000,additional_root_pem_files=[HOME+'/ca1.pem']),'t090',0),('hostname-mismatch',origin.replace('localhost','127.0.0.1'),dict(request_timeout_ms=2000,additional_root_pem_files=[HOME+'/ca1.pem']),'t090',1),('selected-timeout',origin,dict(request_timeout_ms=100,additional_root_pem_files=[HOME+'/ca1.pem']),'delay',1),('normal-recovery',origin,dict(request_timeout_ms=2000,additional_root_pem_files=[HOME+'/ca1.pem']),'t090',0)]:
     config=dict(origin=target)
     if transport is not None:config['transport']=transport
     dump(home/'catalog.json',config);os.chown(home/'catalog.json',65534,65534)
     r=run(label,name,root,['/usr/bin/peerwork','secure','catalog-search',HOME+'/catalog.json',query],expected=None);value=json.loads(r.stdout if code==0 else r.stderr)
     calls.append(dict(name=name,target=target+'/api/protocol-catalog/v1/packages',http_status=200 if r.returncode==0 else None,result=value,exit_code=r.returncode));dump(E/'cli-calls.json',calls)
     assert r.returncode==code
     if code==0:assert json.loads(value['listing_canonical_json'])==dict(items=[],next=None,watermark=0)
     else:assert value['code']=='CATALOG_TRANSPORT_FAILED'

    result=dict(result='PASS',interface='cli',uid=65534,calls=calls,loaded=[dict(path='/usr/bin/peerwork',sha256=sha(root/'usr/bin/peerwork'))])
   assert result['result']=='PASS';results.append(result);dump(E/(label+'-result.json'),result)
   dump(E/(label+'-runtime-after.json'),inventory(root,label))
  assert len(requests)==10 and sum(x['authority']=='ca2' for x in requests)==1 and all(x['method']=='GET' for x in requests),requests
  dump(E/'summary.json',dict(result='PASS',interfaces=results,source=PIN,artifact_manifest_sha256=ARTIFACT,https_gets=10,post_count=0,os_store_plus_explicit_roots=True,physical_absence=True))
 finally:
  for server in servers:server.shutdown();server.server_close()
  for thread in threads:thread.join()
  dump(E/'service-exit.json',dict(closed=True,waited=True,requests=requests,post_count=sum(x['method']=='POST' for x in requests),keys_logged=False))
  after=guard();dump(E/'cohort-after.json',after);assert before==after

if __name__=='__main__':
 os.umask(0o077);start=time.monotonic();began=datetime.datetime.now(datetime.timezone.utc).isoformat()
 try:
  if '--prepare' in sys.argv:prepare()
  else:execute()
 except Exception as error:
  dump(E/('prepare-terminal.json' if '--prepare' in sys.argv else 'terminal.json'),dict(exit_code=1,started=began,ended=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-start,error_type=type(error).__name__));raise
 else:dump(E/('prepare-terminal.json' if '--prepare' in sys.argv else 'terminal.json'),dict(exit_code=0,started=began,ended=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-start))
