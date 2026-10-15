"""Finish only fresh-read recovery on the exact retained service/profile, no new fixture or timeout."""
from pathlib import Path
import hashlib,json,os,selectors,sqlite3,subprocess
from urllib.parse import urlsplit
HERE=Path(__file__).resolve().parent
BASE=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/marker-sdk-t023-20261015');FS=(BASE/'rootfs').resolve();SDK=FS/'work/sdk-marker-t023-20261015';REFERENCE='/root/workdir/message/.worktrees/e2ee-main-integration-20261006'
def verify():
 assert hashlib.sha256((BASE/'artifact-manifest.sha256').read_bytes()).hexdigest()=='85aa7882e72280b896fc3d127627265bc9dbcecd0a2df51c9af40818b5433ea6'
 subprocess.run(['sha256sum','-c','--status',str(BASE/'artifact-manifest.sha256')],cwd=BASE,check=True)
 subprocess.run(['sha256sum','-c','--status',str(BASE/'source-manifest-final.sha256')],cwd=SDK,check=True)
verify();results=[]
overlay=FS/'work/read-controls-t047-resume-overlay';overlay.mkdir(mode=0o700)
for name in ['reference-kernel-server.mjs','consumer.py']:(overlay/name).write_bytes((HERE/name).read_bytes())
for interface in ['python','node','cli']:
 state=FS/'work/read-controls-t047-timeout-only'/interface;fixture=json.loads((state/'host-fixture.json').read_text());port=urlsplit(fixture['origin']).port
 with sqlite3.connect('file:'+str(state/'kernel/control.sqlite')+'?mode=ro',uri=True) as db:
  rows=db.execute('SELECT sequence,commit_hash FROM secure_commits ORDER BY sequence DESC').fetchall();assert len(rows)==53 and rows[0][0]==53
 fixture.update(controls='resume-only',resume_head=rows[0][1]);(state/'resume-fixture.json').write_text(json.dumps(fixture))
 log=state/'kernel/resume-stderr.log';err=log.open('wb');env={k:v for k,v in os.environ.items() if not k.startswith('PEERWORK_TEST_')};env.update(PEERWORK_TEST_RESTART_PROXY_PORT=str(port),PEERWORK_REFERENCE_ROOT=REFERENCE,PEERWORK_TEST_STATE=str(state/'kernel'),PEERWORK_TEST_RESTART_PUBLIC_FIXTURE=str(state/'host-fixture.json'))
 server=subprocess.Popen([str(FS/'opt/node24/bin/node'),str(overlay/'reference-kernel-server.mjs')],env=env,stdout=subprocess.PIPE,stderr=err,text=True)
 try:
  selector=selectors.DefaultSelector();selector.register(server.stdout,selectors.EVENT_READ);assert selector.select(30);ready=json.loads(server.stdout.readline());selector.close();assert ready['origin']==fixture['origin']
  guest='/work/read-controls-t047-timeout-only/'+interface
  program='''root="$1";state="$2";for d in null zero urandom;do mount --bind "/dev/$d" "$root/dev/$d";done
chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/work/sdk-marker-t023-20261015/dist/python-consumer PEERWORK_TEST_SDK_ROOT=/work/sdk-marker-t023-20261015 PEERWORK_TEST_STATE="$state" PEERWORK_TEST_HOST_FIXTURE_JSON="$state/resume-fixture.json" PEERWORK_TEST_NODE=/opt/node24/bin/node PEERWORK_TEST_NODE_PACKAGE=/work/sdk-marker-t023-20261015/dist/node-consumer/node_modules/@peerwork/agent-sdk PEERWORK_TEST_CLI=/work/sdk-marker-t023-20261015/target/release/peerwork /opt/python/cp311-cp311/bin/python -B /work/read-controls-t047-resume-overlay/consumer.py'''
  run=subprocess.run(['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'resume',str(FS),guest],capture_output=True,text=True,timeout=60)
  (state/'resume.stdout').write_text(run.stdout);(state/'resume.stderr').write_text(run.stderr)
  result=dict(interface=interface,exit_code=run.returncode,stdout_sha256=hashlib.sha256(run.stdout.encode()).hexdigest(),stderr_sha256=hashlib.sha256(run.stderr.encode()).hexdigest());results.append(result);print(json.dumps(result),flush=True)
  with sqlite3.connect('file:'+str(state/'kernel/control.sqlite')+'?mode=ro',uri=True) as db:assert db.execute('SELECT count(*) FROM secure_commits').fetchone()==(53,)
 finally:
  server.terminate()
  try:server.wait(timeout=10)
  except subprocess.TimeoutExpired:server.kill();server.wait(timeout=10)
  err.close();(state/'kernel/resume-exit.json').write_text(json.dumps(dict(exit_code=server.returncode,stderr_sha256=hashlib.sha256(log.read_bytes()).hexdigest())))
  verify()
assert len(results)==3 and all(r['exit_code']==0 for r in results)
