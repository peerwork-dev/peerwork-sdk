from pathlib import Path
import hashlib,json,subprocess,shutil,time,datetime
HERE=Path(__file__).resolve().parent;WORK=HERE.parents[1];base=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/marker-sdk-t023-20261015');root=(base/'rootfs').resolve();data=root/'work/t063-local';case=root/'work/t059-archive-service-env-fixed';logs=WORK/'.test-data/t063'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def guard():
 assert sha(base/'artifact-manifest.sha256')=='85aa7882e72280b896fc3d127627265bc9dbcecd0a2df51c9af40818b5433ea6'
 for name,cwd in [('artifact-manifest.sha256',base),('source-manifest-final.sha256',root/'work/sdk-marker-t023-20261015')]:subprocess.run(['sha256sum','-c','--status',str(base/name)],cwd=cwd,check=True)
assert json.loads((logs/'build.terminal.json').read_text())['exit_code']==0;guard()
pins=dict(python_native=sha(WORK/'.build-target/debug/lib_peerwork_native.so'),cli=sha(WORK/'.build-target/debug/peerwork'),source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=WORK,text=True).strip())
(data/'binary-pins.json').write_text(json.dumps(pins)+'\n');(logs/'binary-pins.json').write_text(json.dumps(pins,indent=2)+'\n');shutil.copyfile(WORK/'.build-target/debug/lib_peerwork_native.so',data/'peerwork/_peerwork_native.so')
command=json.loads((data/'command.json').read_text());smoke=command.copy();smoke[-3]=command[-3] if False else smoke[-3]
# Same namespace/userland as the actual consumer, but import only; success gates the service.
smoke=command.copy();smoke[-3]=smoke[-3].replace('/usr/bin/python3 -B /work/t063-local/consumer.py','/usr/bin/python3 -B -c "import peerwork; print(peerwork.version())"')
check=subprocess.run(smoke,capture_output=True,text=True,timeout=20);(logs/'loader-smoke.json').write_text(json.dumps(dict(exit_code=check.returncode,stdout=check.stdout,stderr=check.stderr))+'\n');assert check.returncode==0
start=time.time();utc=lambda:datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC');begin=utc()
try:
 with(logs/'http.log').open('wb')as out:run=subprocess.run(['/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node',str(HERE/'server.mjs'),'/root/workdir/message/.worktrees/e2ee-main-integration-20261006',str(case),str(data/'command.json'),str(data)],stdout=out,stderr=subprocess.STDOUT,timeout=60)
 status=dict(exit_code=run.returncode,started_utc=begin,ended_utc=utc(),duration_seconds=time.time()-start);(logs/'http.terminal.json').write_text(json.dumps(status,indent=2)+'\n');print(json.dumps(status),flush=True)
finally:guard()
assert run.returncode==0
