from pathlib import Path
import hashlib,json,subprocess,shutil,time,datetime,os
W=Path(__file__).resolve().parents[2];E=W/'.test-data/t079/corrected';ROOT=Path('/workspace/peerwork-service');SDK=Path(__file__).resolve().parents[2];OLD=SDK/'.test-data/installed-fixture';STATE=(OLD/'rootfs').resolve()/'work/t059-archive-service-env-fixed';REF=Path('/workspace/peerwork-service');SERVER=SDK/'tests/lifecycle-origin-t063/server.mjs';BIND=SDK/'bindings/python/peerwork';PIN=os.environ['PEERWORK_FIXTURE_SOURCE']
E.mkdir(mode=0o700)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','-C',str(BIND),'rev-parse','HEAD'],text=True).strip()==PIN
assert sha(BIND/'__init__.py')=='c629f6fbae38ce4d50e62be16ab77160c26713a384393ce1e57722e164d553ce'
subprocess.run(['git','-C',str(BIND),'diff','--quiet','HEAD','--','.'],check=True)
package=E/'local-python/peerwork';package.mkdir(parents=True);shutil.copyfile(BIND/'__init__.py',package/'__init__.py');shutil.copyfile(W/'.build-target/debug/lib_peerwork_native.so',package/'_peerwork_native.abi3.so');report=E/'http';report.mkdir(mode=0o700)
metadata={'rust_source':subprocess.check_output(['git','-C',str(W),'rev-parse','HEAD'],text=True).strip(),'python_facade_source':PIN,'native_sha256':sha(package/'_peerwork_native.abi3.so'),'wrapper_sha256':sha(package/'__init__.py'),'server_sha256':sha(SERVER)};(E/'frozen-local.json').write_text(json.dumps(metadata,indent=2)+'\n')
root=(OLD/'rootfs').resolve();overlay=root/'work/t079-count-overlay-corrected';overlay.mkdir(mode=0o700);shutil.copyfile(W/'tests/replay-count-resource/consumer.py',overlay/'consumer.py');(root/'work/t079-local-python-corrected').mkdir(mode=0o700);(root/'work/t079-count-report-corrected').mkdir(mode=0o700)
program='root="$1"; public="$2"; report="$3"; for dir in usr lib lib64;do mount --bind "/$dir" "$root/$dir";done; for device in null zero urandom;do mount --bind "/dev/$device" "$root/dev/$device";done;mount --bind "$public" "$root/work/t079-local-python-corrected";mount --bind "$report" "$root/work/t079-count-report-corrected"; chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/work/t079-local-python-corrected T079_STATE=/work/t059-archive-service-env-fixed T079_REPORT=/work/t079-count-report-corrected /usr/bin/python3 -B /work/t079-count-overlay-corrected/consumer.py'
cmd=['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'t079',str(root),str(package.parent),str(report)];command=E/'http-command.json';command.write_text(json.dumps(cmd,indent=2)+'\n')
start=time.monotonic();began=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (E/'http.log').open('wb') as out:r=subprocess.run([str(Path('/usr/bin/node')),str(SERVER),str(REF),str(STATE),str(command),str(report)],stdout=out,stderr=subprocess.STDOUT,timeout=90)
(E/'http-terminal.json').write_text(json.dumps({'exit_code':r.returncode,'started':began,'ended':datetime.datetime.now(datetime.timezone.utc).isoformat(),'seconds':time.monotonic()-start},indent=2)+'\n');print((E/'http.log').read_text());assert r.returncode==0
assert sha(package/'_peerwork_native.abi3.so')==metadata['native_sha256'] and sha(package/'__init__.py')==metadata['wrapper_sha256']
