from pathlib import Path
import subprocess,json,datetime,time,hashlib,shutil,os
HERE=Path(__file__).resolve().parent;W=HERE.parents[1];E=W/'.test-data/t077';E.mkdir(parents=True,exist_ok=True)
BASE=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/archive-sdk-t064-20261015');ROOT=(BASE/'rootfs').resolve();SDK=ROOT/'work/sdk-config-t062-20261015';REF=Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006');NODE='/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def guard():
 assert sha(BASE/'artifact-manifest.sha256')=='d545bf69b2f84267e777316b0851bd2b2462be6f455f85accc9021de96500868'
 assert sha(BASE/'source-manifest-final.sha256')=='d16f7a04c52f471f051a2c3a0ba006bc26efadcda6ab61c8a56f834293c27911'
 subprocess.run(['sha256sum','-c','--status',str(BASE/'artifact-manifest.sha256')],cwd=BASE,check=True)
 subprocess.run(['sha256sum','-c','--status',str(BASE/'source-manifest-final.sha256')],cwd=SDK,check=True)
# Failure gates must complete before any runtime leaf/service is created.
subprocess.run([NODE,'--check',str(HERE/'fixture.mjs')],check=True)
compile((HERE/'consumer.py').read_text(),str(HERE/'consumer.py'),'exec');guard()
tracer=Path(os.environ['PEERWORK_T076_SOURCE']);qualification=Path(os.environ['PEERWORK_T076_QUALIFICATION']);assert sha(tracer/'trace.py')==os.environ['PEERWORK_T076_TRACE_SHA256'];assert sha(qualification)==os.environ['PEERWORK_T076_QUALIFICATION_SHA256'];q=json.loads(qualification.read_text());assert q['result']=='PASS' and q['positive']['boundary_reached'] and not q['wrong_backup_negative']['boundary_reached'] and not q['short_payload_negative']['boundary_reached']
assert subprocess.check_output(['git','-C',str(tracer),'rev-parse','HEAD'],text=True).strip()==os.environ['PEERWORK_T076_COMMIT'];subprocess.run(['git','-C',str(tracer),'diff','--quiet','HEAD','--','tests/migration-wal-barrier'],check=True)
state=ROOT/'work/t077-migration-crash';overlay=ROOT/'work/t077-crash-overlay';assert not state.exists() and not overlay.exists();overlay.mkdir(mode=0o700);shutil.copyfile(HERE/'consumer.py',overlay/'consumer.py')
for name in ['trace.py','qualify.py','dummy.py']:shutil.copyfile(tracer/name,overlay/name)
(E/'tracer-dependency.json').write_text(json.dumps({'source':str(tracer),'qualification':str(qualification),'qualification_sha256':sha(qualification),'copied_sources':{n:sha(overlay/n) for n in ['trace.py','qualify.py','dummy.py']}},indent=2)+'\n')
program='root="$1"; phase="$2"; mount --bind /proc "$root/proc"; mount -o remount,bind,ro "$root/proc"; for d in null zero urandom;do mount --bind "/dev/$d" "$root/dev/$d";done; chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin PYTHONPATH=/work/sdk-config-t062-20261015/dist/python-consumer PYTHONDONTWRITEBYTECODE=1 /opt/python/cp311-cp311/bin/python -B /work/t077-crash-overlay/consumer.py "$phase"'
commands={phase:['unshare','--user','--map-root-user','--mount','--fork','/bin/bash','-euc',program,'t077',str(ROOT),phase] for phase in ['consumer']}
qualification_argv=commands['consumer'][:-1]+['qualification']
qualification_argv=[v.replace('/work/t077-crash-overlay/consumer.py "$phase"','/work/t077-crash-overlay/qualify.py') if isinstance(v,str) else v for v in qualification_argv]
qt=time.monotonic()
with (E/'namespace-qualification.stdout').open('w') as out,(E/'namespace-qualification.stderr').open('w') as err:qr=subprocess.run(qualification_argv,stdout=out,stderr=err,timeout=45)
(E/'namespace-qualification-terminal.json').write_text(json.dumps({'exit_code':qr.returncode,'seconds':time.monotonic()-qt,'argv':qualification_argv},indent=2)+'\n');assert qr.returncode==0,'qualified tracer failed in consumer namespace; no service launched'
qq=json.loads((E/'namespace-qualification.stdout').read_text());assert qq['result']=='PASS' and qq['positive']['boundary_reached'] and not qq['wrong_backup_negative']['boundary_reached'] and not qq['short_payload_negative']['boundary_reached']
commandfile=E/'commands.json';commandfile.write_text(json.dumps(commands,indent=2)+'\n');commandfile.chmod(0o600)
argv=[NODE,str(HERE/'fixture.mjs'),str(REF),str(state),str(commandfile)];(E/'invocation.json').write_text(json.dumps(argv,indent=2)+'\n');(E/'paths.json').write_text(json.dumps({'state':str(state),'base':str(BASE),'root':str(ROOT)},indent=2)+'\n')
start=time.monotonic();began=datetime.datetime.now(datetime.timezone.utc).isoformat()
try:
 with (E/'actual.log').open('wb') as log:r=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=120)
 terminal=dict(exit_code=r.returncode,started=began,ended=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-start);(E/'terminal.json').write_text(json.dumps(terminal,indent=2)+'\n');print(json.dumps(terminal));print((E/'actual.log').read_text()[-3500:])
finally:guard()
raise SystemExit(r.returncode)
