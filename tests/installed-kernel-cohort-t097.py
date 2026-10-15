"""Fresh UID65534 offline installation and installed-only T094 regression."""
from pathlib import Path
import os,sys,json,subprocess,shutil,time,datetime,hashlib
GUEST='/work/sdk-config-t062-20261015';HOME='/work/t097 installed 用户';NODE='/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node';REF='/root/workdir/message/.worktrees/e2ee-main-integration-20261006'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def offline():
 assert os.geteuid()==65534;os.umask(0o077);h=Path(HOME);os.chdir(h);calls=[]
 def run(argv):
  t=time.monotonic();r=subprocess.run(argv,capture_output=True,text=True);calls.append(dict(argv=argv,exit_code=r.returncode,seconds=time.monotonic()-t,stdout=r.stdout,stderr=r.stderr));(h/'offline-calls.json').write_text(json.dumps(calls,indent=2));assert r.returncode==0,r.stderr;return r.stdout
 py='/opt/python/cp311-cp311/bin/python';node='/opt/node24/bin/node'
 run([py,'-m','pip','install','--no-index','--no-deps','--target',HOME+'/python',GUEST+'/dist/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl'])
 np=h/'node';np.mkdir();(np/'package.json').write_text('{"name":"t097-offline","private":true}')
 run(['/opt/node24/bin/npm','install','--prefix',str(np),'--cache',HOME+'/npm-cache','--offline','--ignore-scripts','--no-audit','--no-fund','--no-save',GUEST+'/dist/npm/peerwork-agent-sdk-0.0.1.tgz',GUEST+'/dist/npm/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz'])
 (h/'bin').mkdir();cli=h/'bin/peerwork';shutil.copy2(GUEST+'/target/release/peerwork',cli)
 sys.path.insert(0,HOME+'/python');import peerwork,peerwork._peerwork_native as native
 assert issubclass(peerwork.KernelError,RuntimeError)
 profile=h/'offline-profile';profile.mkdir(mode=0o700);info=peerwork.create_identity(str(profile/'identity'))
 assert peerwork.open_identity(str(profile/'identity'))==info
 assert json.loads(run([str(cli),'identity','info',str(profile/'identity')]))==info
 run([str(cli),'kernel','--help']) if False else run([str(cli),'--help'])
 js="const s=require(process.argv[1]);if(!(new s.KernelError('X','fixed') instanceof Error))throw Error('class');console.log(JSON.stringify({entry:require.resolve(process.argv[1]),native:Object.keys(require.cache).find(p=>p.endsWith('.node')),version:process.version}));"
 n=json.loads(run([node,'-e',js,HOME+'/node/node_modules/@peerwork/agent-sdk']))
 files=[Path(peerwork.__file__),Path(native.__file__),Path(n['entry']),Path(n['native']),cli]
 expected=[Path(GUEST+'/dist/python-consumer/peerwork/__init__.py'),Path(GUEST+'/dist/python-consumer/peerwork/_peerwork_native.abi3.so'),Path(GUEST+'/dist/node-consumer/node_modules/@peerwork/agent-sdk/index.cjs'),Path(GUEST+'/dist/node-consumer/node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node'),Path(GUEST+'/target/release/peerwork')]
 assert [sha(p)for p in files]==[sha(p)for p in expected]
 result=dict(status='PASS',uid=os.getuid(),euid=os.geteuid(),python_runtime=sys.version,node=n,version=peerwork.version(),files=[dict(path=str(p),sha256=sha(p),bytes=p.stat().st_size)for p in files],identity_public=info)
 (h/'offline-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
def host(base):
 b=Path(base).resolve();root=b/'rootfs';source=root/GUEST.lstrip('/');h=root/HOME.lstrip('/');h.mkdir(mode=0o700,exist_ok='--continue' in sys.argv);os.chown(h,65534,65534)
 def guard():
  for file,cwd in [('source-manifest-final.sha256',source),('artifact-manifest.sha256',b)]:subprocess.run(['sha256sum','-c','--status',str(b/file)],cwd=cwd,check=True)
 guard();shutil.copy2(__file__,h/'offline.py');os.chown(h/'offline.py',65534,65534)
 def run(label,guest_script,extra=()):
  argv=['/usr/sbin/chroot','--userspec=65534:65534',str(root),'/usr/bin/env','-i','HOME='+HOME,'PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1','PIP_DISABLE_PIP_VERSION_CHECK=1',*extra,'/opt/python/cp311-cp311/bin/python','-I',guest_script]
  t=time.monotonic();start=datetime.datetime.now(datetime.timezone.utc).isoformat()
  with(b/(label+'.stdout')).open('w')as out,(b/(label+'.stderr')).open('w')as err:r=subprocess.run(argv,stdout=out,stderr=err)
  record=dict(argv=argv,start=start,end=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-t,exit_code=r.returncode)
  (b/(label+'.terminal.json')).write_text(json.dumps(record,indent=2));assert r.returncode==0,record
 if '--continue' not in sys.argv:run('offline',HOME+'/offline.py',('PEERWORK_T097_CHILD=1',))
 raw=(source/'tests/kernel-errors-t094/host.py').read_text();a=raw.index('ROOT=Path(');z=raw.index('def run(',a)
 replacement=f'''ROOT=Path({GUEST!r});OUT=Path({HOME!r})/'http-first';C=Path({HOME!r})
NODE='/opt/node24/bin/node'
os.umask(0o077);OUT.mkdir(mode=0o700,exist_ok=True);assert os.geteuid()==65534
sys.path.insert(0,str(C/'python'));import peerwork
assert Path(peerwork.__file__).resolve()==C/'python/peerwork/__init__.py'
entry=C/'node/node_modules/@peerwork/agent-sdk/index.cjs'
CLI=str(C/'bin/peerwork');calls=[]
'''
 raw=raw[:a]+replacement+raw[z:]
 a=raw.index("service=OUT/'reference'");z=raw.index(" for language in ['python','node','cli']:",a)
 raw=raw[:a]+"results={}\ntry:\n origin=os.environ['PEERWORK_T097_ORIGIN']\n"+raw[z:]
 a=raw.index("bad.shutdown();bad.server_close();thread.join();server.terminate()")
 raw=raw[:a]+"bad.shutdown();bad.server_close();thread.join();(OUT/'shutdown.json').write_text(json.dumps(dict(failure_server_closed=True,reference_owned_by_host=True)))\n"
 raw=raw.replace("{str(p.relative_to(C)):shafile(p) for p in C.rglob('*') if p.is_file()}","{str(p):shafile(p) for p in [C/'bin/peerwork',C/'python/peerwork/__init__.py',C/'python/peerwork/_peerwork_native.abi3.so',entry,C/'node/node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node']}")
 raw=raw.replace("case.mkdir(mode=0o700)","case.mkdir(mode=0o700,exist_ok=True)").replace("info=run([CLI,'identity','create',identity])", "info=run([CLI,'identity','info' if identity.exists() else 'create',identity])")
 raw=raw.replace("assert isinstance(e,RuntimeError) and e.code==code;return dict", "(OUT/('error-'+mode+'-python.json')).write_text(json.dumps(dict(code=e.code,message=str(e),operation='open',target=selected)));assert isinstance(e,RuntimeError) and e.code==code;return dict")
 compile(raw,'derived-http.py','exec');(h/'http.py').write_text(raw);os.chown(h/'http.py',65534,65534);(b/'derived-http-source.sha256').write_text(sha(h/'http.py')+'\n')
 state=b/'http-service';state.mkdir(mode=0o700,exist_ok=True);env=os.environ.copy();env.update(PEERWORK_REFERENCE_ROOT=REF,PEERWORK_TEST_STATE=str(state),PEERWORK_TEST_FIRST_POST_MODE='normal');env.pop('PEERWORK_HTTP_PROXY',None)
 with(b/'service.stderr').open('w')as err:
  server=subprocess.Popen([NODE,str(source/'tests/reference-kernel-server.mjs')],env=env,stdout=subprocess.PIPE,stderr=err,text=True)
  try:
   line=server.stdout.readline();assert line,'reference startup failed';origin=json.loads(line)['origin'];(b/'service-ready.json').write_text(line)
   import urllib.request
   with urllib.request.urlopen(origin+'__test/counts')as response:baseline=json.load(response)
   (b/'http-baseline-counts.json').write_text(json.dumps(baseline));assert baseline['commands']==0
   run('http',HOME+'/http.py',('PEERWORK_T097_ORIGIN='+origin,))
  finally:
   server.terminate();status=server.wait(timeout=10);(b/'service-shutdown.json').write_text(json.dumps(dict(exit_code=status,waited=True)))
 guard()
 result=dict(status='PASS',source=json.loads((b/'cohort-source.json').read_text())['source_commit'],artifact_manifest_sha256=sha(b/'artifact-manifest.sha256'),offline=json.loads((h/'offline-result.json').read_text()),http=json.loads((h/'http-first/summary.json').read_text()),service_shutdown=json.loads((b/'service-shutdown.json').read_text()),service_stderr_bytes=(b/'service.stderr').stat().st_size,post_guards='PASS')
 (b/'installed-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(dict(status='PASS',uid=result['offline']['uid'],interfaces=list(result['http']['results']),counts=result['http']['counts'])))
if __name__=='__main__':offline()if os.environ.get('PEERWORK_T097_CHILD')else host(sys.argv[1])
