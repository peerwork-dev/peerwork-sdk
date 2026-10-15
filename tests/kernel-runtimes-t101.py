"""Existing pinned extra runtimes against only frozen T097 installed bytes."""
from pathlib import Path
import os,sys,json,subprocess,hashlib,shutil,time,datetime
NODE='/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node';REF='/root/workdir/message/.worktrees/e2ee-main-integration-20261006'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def child():
 assert os.geteuid()==65534;os.umask(0o077);h=Path(os.environ['HOME']);language=os.environ['PEERWORK_T101_LANGUAGE'];calls=[]
 def run(argv):
  t=time.monotonic();p=subprocess.run(argv,capture_output=True,text=True);calls.append(dict(argv=argv,exit_code=p.returncode,seconds=time.monotonic()-t,stdout=p.stdout,stderr=p.stderr));(h/'install-calls.json').write_text(json.dumps(calls,indent=2));assert p.returncode==0,p.stderr
 if language=='python':run([sys.executable,'-I','-B','-m','pip','install','--no-index','--no-deps','--target',str(h/'python'),'/work/artifacts/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl'])
 else:
  (h/'node').mkdir();(h/'node/package.json').write_text('{"name":"t101-offline","private":true}')
  run(['/opt/node22/bin/npm','install','--prefix',str(h/'node'),'--cache',str(h/'npm-cache'),'--offline','--ignore-scripts','--omit=optional','--no-audit','--no-fund','--no-save','/work/artifacts/peerwork-agent-sdk-0.0.1.tgz','/work/artifacts/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz'])
 (h/'bin').mkdir();shutil.copy2('/work/artifacts/peerwork',h/'bin/peerwork')
 exec(compile((h/'http.py').read_text(),str(h/'http.py'),'exec'),globals())
def host(base):
 b=Path(base).resolve();root=b/'runtime-root';sdk=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012');cohort=sdk/'.build-artifacts/kernel-sdk-t097-20261015';source=cohort/'rootfs/work/sdk-config-t062-20261015'
 def guard():
  for name,cwd in [('source-manifest-final.sha256',source),('artifact-manifest.sha256',cohort)]:subprocess.run(['sha256sum','-c','--status',str(cohort/name)],cwd=cwd,check=True)
 guard();cases=json.loads((b/'admission.json').read_text())['runtimes'];cases += [dict(name='node22',version='22.23.0',executable='/opt/python/cp312-cp312/bin/python')]
 original=(source/'tests/kernel-errors-t094/host.py').read_text();helper=root/'work/tests/kernel-errors-t094/node.cjs';helper.parent.mkdir(parents=True)
 node=(source/'tests/kernel-errors-t094/node.cjs').read_text();node=node.replace("catch(error) { if", "catch(error) { fs.writeFileSync(x.errorLog,JSON.stringify({code:error.code,message:error.message,operation:'open',target:x.origin})); if",1)
 node=node.replace("{pending:p,status,result,retry}","{pending:p,status,result,retry,runtime:process.version,execPath:process.execPath,wrapper:require.resolve(process.argv[2]),native:Object.keys(require.cache).find(p=>p.endsWith('.node'))}")
 helper.write_text(node);results=[];statuses=[];state=b/'service';state.mkdir(mode=0o700);env=os.environ.copy();env.update(PEERWORK_REFERENCE_ROOT=REF,PEERWORK_TEST_STATE=str(state),PEERWORK_TEST_FIRST_POST_MODE='normal');env.pop('PEERWORK_HTTP_PROXY',None)
 with(b/'service.stderr').open('w')as err:
  server=subprocess.Popen([NODE,str(source/'tests/reference-kernel-server.mjs')],env=env,stdout=subprocess.PIPE,stderr=err,text=True)
  try:
   line=server.stdout.readline();assert line;origin=json.loads(line)['origin'];(b/'service-ready.json').write_text(line)
   for index,case in enumerate(cases):
    language='node'if case['name']=='node22'else'python';home='/work/t101 '+case['name']+' 用户';h=root/home.lstrip('/');h.mkdir(mode=0o700);os.chown(h,65534,65534);shutil.copy2(__file__,h/'child.py');os.chown(h/'child.py',65534,65534)
    raw=original;a=raw.index('ROOT=Path(');z=raw.index('def run(',a)
    top=f'''ROOT=Path('/work');OUT=Path({home!r})/'http';C=Path({home!r})
NODE='/opt/node22/bin/node';LANGUAGE={language!r}
os.umask(0o077);OUT.mkdir(mode=0o700);assert os.geteuid()==65534
if LANGUAGE=='python':
 import sysconfig
 assert sysconfig.get_config_var('Py_GIL_DISABLED')!=1
 assert not hasattr(sys,'_is_gil_enabled') or sys._is_gil_enabled()
 sys.path.insert(0,str(C/'python'));import peerwork
 assert Path(peerwork.__file__).resolve()==C/'python/peerwork/__init__.py'
entry=C/'node/node_modules/@peerwork/agent-sdk/index.cjs';CLI=str(C/'bin/peerwork');calls=[]
'''
    raw=raw[:a]+top+raw[z:];a=raw.index("service=OUT/'reference'");z=raw.index(" for language in ['python','node','cli']:",a)
    raw=raw[:a]+"results={}\ntry:\n origin=os.environ['PEERWORK_T101_ORIGIN']\n"+raw[z:];raw=raw.replace("for language in ['python','node','cli']:","for language in [LANGUAGE]:")
    a=raw.index("bad.shutdown();bad.server_close();thread.join();server.terminate()");raw=raw[:a]+"bad.shutdown();bad.server_close();thread.join();(OUT/'shutdown.json').write_text(json.dumps(dict(failure_server_closed=True,reference_owned_by_host=True)))\n"
    raw=raw.replace("assert len(failures)==3", "assert len(failures)==1").replace("assert counts['commands']==3", "assert counts['commands']==int(os.environ['PEERWORK_T101_EXPECTED'])")
    raw=raw.replace("code=code,command=command)","code=code,command=command,errorLog=str(case/(mode+'-error.json')))")
    raw=raw.replace("assert isinstance(e,RuntimeError) and e.code==code;return dict", "(OUT/('error-'+mode+'-python.json')).write_text(json.dumps(dict(code=e.code,message=str(e),operation='open',target=selected)));assert isinstance(e,RuntimeError) and e.code==code;return dict")
    raw=raw.replace("python_module=peerwork.__file__", "python_module=peerwork.__file__ if LANGUAGE=='python' else None,python_runtime=sys.version if LANGUAGE=='python' else None,gil=LANGUAGE=='python'")
    raw=raw.replace("{str(p.relative_to(C)):shafile(p) for p in C.rglob('*') if p.is_file()}","{str(p):shafile(p) for p in [C/'bin/peerwork']+([C/'python/peerwork/__init__.py',C/'python/peerwork/_peerwork_native.abi3.so'] if LANGUAGE=='python' else [entry,C/'node/node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node'])}")
    compile(raw,'t101-http.py','exec');(h/'http.py').write_text(raw);os.chown(h/'http.py',65534,65534)
    argv=['/usr/sbin/chroot','--userspec=65534:65534',str(root),'/usr/bin/env','-i','HOME='+home,'PATH=/opt/node22/bin:/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1','PIP_DISABLE_PIP_VERSION_CHECK=1','PEERWORK_T101_CHILD=1','PEERWORK_T101_LANGUAGE='+language,'PEERWORK_T101_ORIGIN='+origin,'PEERWORK_T101_EXPECTED='+str(index+1),case['executable'],'-I','-B',home+'/child.py']
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic()
    with(b/(case['name']+'.stdout')).open('w')as out,(b/(case['name']+'.stderr')).open('w')as error:p=subprocess.run(argv,stdout=out,stderr=error)
    status=dict(case=case['name'],argv=argv,start=start,end=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-t,exit_code=p.returncode);statuses.append(status);(b/'terminals.json').write_text(json.dumps(statuses,indent=2));assert p.returncode==0,status
    result=json.loads((h/'http/summary.json').read_text());assert len(result['executables'])==3
    # The canonical subject bytes come from the exact installed T097 packages.
    expected={'peerwork':sha(source/'target/release/peerwork'),'__init__.py':sha(source/'dist/python-consumer/peerwork/__init__.py'),'_peerwork_native.abi3.so':sha(source/'dist/python-consumer/peerwork/_peerwork_native.abi3.so'),'index.cjs':sha(source/'dist/node-consumer/node_modules/@peerwork/agent-sdk/index.cjs'),'index.node':sha(source/'dist/node-consumer/node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node')}
    for path,digest in result['executables'].items():assert digest==expected[Path(path).name]
    if language=='node':assert result['results']['node']['success']['runtime']=='v22.23.0'
    results.append(dict(case=case['name'],uid=65534,summary=result))
    for name in ['install-calls.json','http.py','http/calls.json','http/summary.json','http/shutdown.json']:
     shutil.copy2(h/name,b/(case['name']+'-'+Path(name).name))
    guard()
  finally:
   server.terminate();exit_code=server.wait(timeout=10);(b/'service-shutdown.json').write_text(json.dumps(dict(exit_code=exit_code,waited=True)))
 guard();assert len(results)==4 and results[-1]['summary']['counts']['commands']==4 and results[-1]['summary']['counts']['workspaces']==4
 (b/'result.json').write_text(json.dumps(dict(status='PASS',source='0daef2a865bc3b09b7c76274883d47680668051c',artifact_manifest_sha256=sha(cohort/'artifact-manifest.sha256'),cases=results,terminals=statuses,source_artifact_guards=0,stderr_bytes=(b/'service.stderr').stat().st_size),indent=2));print(json.dumps(dict(status='PASS',cases=[r['case']for r in results],commands=4,workspaces=4)))
if __name__=='__main__':child()if os.environ.get('PEERWORK_T101_CHILD')else host(sys.argv[1])
