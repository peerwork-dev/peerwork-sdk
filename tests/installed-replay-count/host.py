"""Read-only installed modules over the unchanged existing synthetic profile."""
from pathlib import Path
import os,sys,json,hashlib,subprocess,shutil,time,datetime
W=Path(__file__).resolve().parents[2];HERE=Path(__file__).parent;E=W/'.test-data/t083';E.mkdir(parents=True,exist_ok=True)
ROOT=Path('/root/workdir/message');SDK=ROOT/'.worktrees/peerwork-sdk-native-20261012';BASE=SDK/'.build-artifacts/resource-sdk-t082-20261015'
REF=ROOT/'.worktrees/e2ee-main-integration-20261006';NODE=ROOT/'.tools/node-v24.20.0-linux-x64/bin/node'
OLD=SDK/'.build-artifacts/marker-sdk-t023-20261015';ROOTFS=(OLD/'rootfs').resolve();STATE=ROOTFS/'work/t059-archive-service-env-fixed'
SOURCE='a69929f1e1d44612b92be007df17ecb750529df5';MANIFEST='2bc8abf8c52dbb93aa32ff3545cce08c2139d4d778c6fedda31436386a7641f0'
ARTIFACT=os.environ['PEERWORK_T083_ARTIFACT_MANIFEST_SHA256'];assert len(ARTIFACT)==64
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n');p.chmod(0o600)
def guard():
 assert sha(BASE/'source-manifest-final.sha256')==MANIFEST and sha(BASE/'artifact-manifest.sha256')==ARTIFACT
 meta=json.loads((BASE/'cohort-source.json').read_text());assert meta['source_commit']==SOURCE and meta['source_files']==797
 for name in ['build.terminal.json','install.terminal.json','verify.terminal.json']:
  assert json.loads((BASE/name).read_text())['exit_code']==0, name
 rows=[]
 for line in (BASE/'artifact-manifest.sha256').read_text().splitlines():
  digest,rel=line.split(None,1);p=BASE/rel.lstrip('*');assert sha(p)==digest;rows.append(dict(path=str(p),sha256=digest,size=p.stat().st_size))
 assert len(rows)==14
 return rows
# Gate all runtime-directory creation and service launch on the accepted artifact/installer results.
before=guard();save(E/'guard-before.json',before)
for file in ['node.cjs','server.mjs']:subprocess.run([str(NODE),'--check',str(HERE/file)],check=True)
compile((HERE/'consumer.py').read_text(),str(HERE/'consumer.py'),'exec')
assert subprocess.check_output(['git','-C',str(REF),'rev-parse','HEAD'],text=True).strip()=='f828b6c50a0a58d1e718af90f653b214adcc3328'
subprocess.run(['git','-C',str(REF),'diff','--quiet','HEAD','--','src','tests','scripts','protocols','package.json','package-lock.json','tsconfig.workspace.json'],check=True)
compiled=REF/'dist-workspace/src';files=sorted(compiled.rglob('*.js'));h=hashlib.sha256()
for p in files:h.update(str(p.relative_to(compiled)).encode()+b'\0'+sha(p).encode()+b'\n')
assert len(files)==204 and h.hexdigest()=='6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc'
public=BASE/'rootfs/work/sdk-config-t062-20261015';py=public/'dist/python-consumer';node_modules=public/'dist/node-consumer/node_modules';cli=public/'target/release/peerwork'
for p in [py/'peerwork/__init__.py',py/'peerwork/_peerwork_native.abi3.so',node_modules/'@peerwork/agent-sdk/index.cjs',node_modules/'@peerwork/agent-sdk-linux-x64-gnu/index.node',cli]:assert p.is_file()
guest='/work/t083-installed-count';runtime=ROOTFS/guest.lstrip('/');assert not runtime.exists();runtime.mkdir(mode=0o700)
for name in ['python','node_modules','report','overlay']:(runtime/name).mkdir(mode=0o700)
for name in ['cli','node-runtime']:(runtime/name).touch(mode=0o600)
for name in ['consumer.py','node.cjs']:shutil.copyfile(HERE/name,runtime/'overlay'/name)
report=E/'http';report.mkdir(mode=0o700)
program=r'''root="$1"; py="$2"; modules="$3"; cli="$4"; node="$5"; report="$6"; guest=/work/t083-installed-count
for dir in usr lib lib64;do mount --bind "/$dir" "$root/$dir";done
for device in null zero urandom;do mount --bind "/dev/$device" "$root/dev/$device";done
robind(){ mount --bind "$1" "$2";mount -o remount,bind,ro "$2"; }
robind "$py" "$root$guest/python";robind "$modules" "$root$guest/node_modules";robind "$cli" "$root$guest/cli";robind "$node" "$root$guest/node-runtime"
mount --bind "$report" "$root$guest/report"
chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$guest/python T083_STATE=/work/t059-archive-service-env-fixed T083_REPORT=$guest/report T083_NODE=$guest/node-runtime T083_NODE_MODULES=$guest/node_modules T083_NODE_PACKAGE=$guest/node_modules/@peerwork/agent-sdk T083_CLI=$guest/cli /usr/bin/python3 -B $guest/overlay/consumer.py'''
cmd=['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'t083',str(ROOTFS),str(py),str(node_modules),str(cli),str(NODE),str(report)]
save(E/'command.json',cmd);save(E/'frozen-inputs.json',dict(source=SOURCE,source_manifest_sha256=MANIFEST,artifact_manifest_sha256=ARTIFACT,reference_source='f828b6c50a0a58d1e718af90f653b214adcc3328',files=[dict(path=str(p),sha256=sha(p),size=p.stat().st_size) for p in [HERE/'consumer.py',HERE/'node.cjs',HERE/'server.mjs',py/'peerwork/__init__.py',py/'peerwork/_peerwork_native.abi3.so',node_modules/'@peerwork/agent-sdk/index.cjs',node_modules/'@peerwork/agent-sdk-linux-x64-gnu/index.node',cli,NODE]]))
start=time.monotonic();began=datetime.datetime.now(datetime.timezone.utc).isoformat()
try:
 with (E/'http.log').open('wb') as out:r=subprocess.run([str(NODE),str(HERE/'server.mjs'),str(REF),str(STATE),str(E/'command.json'),str(report)],stdout=out,stderr=subprocess.STDOUT,timeout=180)
 save(E/'terminal.json',dict(exit_code=r.returncode,started=began,ended=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-start))
 print((E/'http.log').read_text());assert r.returncode==0
finally:
 after=guard();save(E/'guard-after.json',after);assert before==after
