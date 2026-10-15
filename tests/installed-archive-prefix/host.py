from pathlib import Path
import hashlib,json,os,shutil,subprocess,time,datetime
HERE=Path(__file__).resolve().parent;SDKMAIN=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012');COHORT=SDKMAIN/'.build-artifacts/marker-sdk-t023-20261015';ROOT=(COHORT/'rootfs').resolve();SDK=ROOT/'work/sdk-marker-t023-20261015';REF=Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def guard():
 assert sha(COHORT/'artifact-manifest.sha256')=='85aa7882e72280b896fc3d127627265bc9dbcecd0a2df51c9af40818b5433ea6'
 assert sha(COHORT/'source-manifest-final.sha256')=='9e2900b85d4097ab3e3b0e9f403f5a56ff22442a3e90df857e6f83f91d083e0e'
 subprocess.run(['sha256sum','-c','--status',str(COHORT/'artifact-manifest.sha256')],cwd=COHORT,check=True);subprocess.run(['sha256sum','-c','--status',str(COHORT/'source-manifest-final.sha256')],cwd=SDK,check=True)
guard();state=ROOT/'work/t059-archive-service-env-fixed';assert not state.exists();overlay=ROOT/'work/t059-archive-overlay-service-env-fixed';assert not overlay.exists();overlay.mkdir(mode=0o700);shutil.copyfile(HERE/'consumer.py',overlay/'consumer.py')
program='''task_root="$1";
for device in null zero urandom;do mount --bind "/dev/$device" "$task_root/dev/$device";done
chroot "$task_root" /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 T059_STATE=/work/t059-archive-service-env-fixed PYTHONPATH=/work/sdk-marker-t023-20261015/dist/python-consumer /opt/python/cp311-cp311/bin/python -B /work/t059-archive-overlay-service-env-fixed/consumer.py
'''
command=['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'t059',str(ROOT)];commandfile=overlay/'command.json';commandfile.write_text(json.dumps(command));commandfile.chmod(0o600)
start=time.time();utc=lambda:datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC');started=utc();log=HERE.parent.parent/'.test-data/t059';log.mkdir(parents=True,exist_ok=True)
try:
 with (log/'host.log').open('wb') as out:run=subprocess.run(['/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node',str(HERE/'fixture.mjs'),str(REF),str(state),str(commandfile)],stdout=out,stderr=subprocess.STDOUT,timeout=180)
 terminal=dict(exit_code=run.returncode,started_utc=started,ended_utc=utc(),duration_seconds=time.time()-start,fixture_path=str(state));(log/'terminal.json').write_text(json.dumps(terminal,indent=2)+'\n');print(json.dumps(terminal),flush=True)
finally:guard()
assert run.returncode==0,'preserved fixture/consumer failure; inspect protected host.log'
