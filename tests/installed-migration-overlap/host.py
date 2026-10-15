from pathlib import Path
import os,sys,json,hashlib,subprocess,time,datetime
W=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent;E=W/'.test-data/t093';E.mkdir(parents=True,exist_ok=True)
B=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/transport-sdk-t089-20261015');SDK=B/'rootfs/work/sdk-config-t062-20261015';S=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/archive-sdk-t064-20261015/rootfs/work/t077-migration-crash');R=S.parent/'t093-migration-overlap';REF=Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006');NODE='/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def guard():
 assert sha(B/'artifact-manifest.sha256')=='f94ac1ae771281800ec7e2d89e12a882a157e261e45e81579872e12cc94658e9'
 assert sha(B/'source-manifest-final.sha256')=='8d5014f36469247b01872b2d84d37e9937d148b0f26647a4e05cdce08d035368'
 subprocess.run(['sha256sum','-c','--status',str(B/'artifact-manifest.sha256')],cwd=B,check=True)
 subprocess.run(['sha256sum','-c','--status',str(B/'source-manifest-final.sha256')],cwd=SDK,check=True)
for f in HERE.glob('*.py'):compile(f.read_text(),str(f),'exec')
subprocess.run([NODE,'--check',str(HERE/'server.mjs')],check=True)
assert subprocess.check_output(['git','-C',str(REF),'rev-parse','HEAD'],text=True).strip()=='f828b6c50a0a58d1e718af90f653b214adcc3328'
subprocess.run(['git','-C',str(REF),'diff','--quiet','HEAD','--','src','package.json','package-lock.json'],check=True)
assert sha(HERE/'trace.py')=='3978513ce2fb6f575fe1a4da72bbfbcd56ed2b05bd67bfe57e734b9de0778ef8'
qualification=json.loads((E/'qualification-final.stdout').read_text());assert qualification['result']=='PASS' and len(qualification['cases'])==5
assert os.environ.get('PEERWORK_T093_CONTROL_RELEASE')=='02beef5','root-qualified source release required'
guard();assert not R.exists()
env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(SDK/'dist/python-consumer'),'PYTHONDONTWRITEBYTECODE':'1','T093_SOURCE':str(S),'T093_RUNTIME':str(R),'T093_SDK':str(SDK)}
argv=['/usr/bin/python3','-B',str(HERE/'consumer.py')]
(E/'command.json').write_text(json.dumps({'argv':argv,'env':env,'evidence':str(E)},indent=2)+'\n');(E/'paths.json').write_text(json.dumps({'source_runtime':str(S),'new_runtime':str(R),'cohort':str(B),'sdk':str(SDK)},indent=2)+'\n')
command=[NODE,str(HERE/'server.mjs'),str(REF),str(S),str(R),str(E/'command.json')];(E/'invocation.json').write_text(json.dumps(command)+'\n')
started=datetime.datetime.now(datetime.timezone.utc).isoformat();begin=time.monotonic()
try:
 with (E/'actual.stdout').open('wb') as out,(E/'actual.stderr').open('wb') as err:result=subprocess.run(command,stdout=out,stderr=err,timeout=80)
 terminal={'exit_code':result.returncode,'started':started,'ended':datetime.datetime.now(datetime.timezone.utc).isoformat(),'seconds':time.monotonic()-begin};(E/'terminal.json').write_text(json.dumps(terminal,indent=2)+'\n');print(json.dumps(terminal))
finally:guard()
raise SystemExit(result.returncode)
