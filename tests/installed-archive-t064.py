#!/usr/bin/env python3
"""Installed corrected SDK against the existing T059/T063 archive profile; no private-state copies."""
from pathlib import Path
import os,sys,json,hashlib,subprocess,shutil,time,datetime,urllib.request
SOURCE='52a1f100ef735d25f237d2df2db796f0fd718ad0'
MAIN=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012')
BASE=MAIN/'.build-artifacts/archive-sdk-t064-20261015'
GUEST='/work/sdk-config-t062-20261015'
def consume(loader=False):
    import peerwork,peerwork._peerwork_native as extension
    assert peerwork.__file__=='/work/t064-new-python/peerwork/__init__.py'
    assert extension.__file__=='/work/t064-new-python/peerwork/_peerwork_native.abi3.so'
    digest=hashlib.sha256(Path(extension.__file__).read_bytes()).hexdigest();assert digest==os.environ['PEERWORK_TEST_EXPECTED_NATIVE_SHA256']
    if loader:print(json.dumps(dict(wrapper=peerwork.__file__,native=extension.__file__,sha256=digest,version=peerwork.version())));return
    state=Path('/work/t059-archive-service-env-fixed');data=Path('/work/t064-installed-archive');f=json.loads((state/'fixture.json').read_text());reference=json.loads((state/'reference-objects.json').read_text())
    assert len(reference)==25
    for name in ['exported-ts-state.json','intents.sqlite','selected-owner.pem']:assert not(state/name).exists()
    def owner():return peerwork.SecureOwnerWorkspaceClient(f['origin'],str(state/'native'),allow_loopback_http=True)
    def save(name,value):(data/name).write_text(json.dumps(value,sort_keys=True)+'\n')
    history=owner().attachments();assert len(history)==1 and history[0]['status']=='ATTACHED' and history[0]['sequence']==27
    id=history[0]['attach_id'];assert id=='NGchyCgRWkgC4zk5J4KKok6jbjRMbdLQbQYhf7oVu5k'
    progress=owner().resume_attachment(id);assert progress==history[0];save('inventory.json',history)
    ordered=lambda x:sorted(json.dumps(o,sort_keys=True,separators=(',',':'))for o in x)
    def check(v):
        assert v['workspace_id']==f['workspace_id'] and v['sequence']==27 and v['head']==f['head'] and v['policy_hash']==f['policy_hash'] and v['structure_status']=='UNSTRUCTURED'
        assert len(v['objects'])==25 and ordered(v['objects'])==ordered(reference)
    first=owner().read(f['workspace_id']);check(first);save('first-read.json',first)
    reopened=owner().read(f['workspace_id']);check(reopened);assert reopened==first
    def route(name):
        with urllib.request.urlopen(f['origin'].rstrip('/')+'/__test/'+name,timeout=10)as r:return json.load(r)
    route('missing')
    try:
        try:owner().read(f['workspace_id']);raise AssertionError('missing archive returned verified result')
        except peerwork.OwnerWorkspaceError as error:negative=dict(code=error.code,no_verified_result=True);assert error.code=='VERIFICATION_FAILED';save('negative.json',negative)
    finally:route('normal')
    recovered=owner().read(f['workspace_id']);check(recovered);assert recovered==first;save('recovered-read.json',recovered)
    assert owner().attachments()==history and owner().resume_attachment(id)==progress
    result=dict(result='PASS',classification='installed release Python from frozen52a; existing protected profile/database',source=SOURCE,original_attach_id=id,status='ATTACHED',same_operation=True,source_exports_gone=True,raw_origin=f['origin'],sequence=27,head=f['head'],policy_hash=f['policy_hash'],objects=25,negative=negative,idempotent=True,wrapper=peerwork.__file__,native=extension.__file__,native_sha256=digest)
    save('effects.json',result);print(json.dumps(result),flush=True)
def host():
    work=Path(__file__).resolve().parents[1];logs=BASE/'archive-results';logs.mkdir(mode=0o700);oldbase=MAIN/'.build-artifacts/marker-sdk-t023-20261015';oldroot=(oldbase/'rootfs').resolve();case=oldroot/'work/t059-archive-service-env-fixed';data=oldroot/'work/t064-installed-archive';data.mkdir(mode=0o700);mount=oldroot/'work/t064-new-python';mount.mkdir()
    public=BASE/'rootfs/work/sdk-config-t062-20261015/dist/python-consumer';shutil.copy2(__file__,data/'consumer.py')
    native_sha=hashlib.sha256((public/'peerwork/_peerwork_native.abi3.so').read_bytes()).hexdigest()
    before=json.loads((case/'fixture.json').read_text());assert before['origin']=='http://127.0.0.1:34635'
    for name in ['exported-ts-state.json','intents.sqlite','selected-owner.pem']:assert not(case/name).exists()
    def guard():
        for name,cwd in [('artifact-manifest.sha256',BASE),('source-manifest-final.sha256',BASE/'rootfs/work/sdk-config-t062-20261015'),('artifact-manifest.sha256',oldbase),('source-manifest-final.sha256',oldroot/'work/sdk-marker-t023-20261015')]:subprocess.run(['sha256sum','-c','--status',str((BASE if cwd==BASE or cwd==BASE/'rootfs/work/sdk-config-t062-20261015' else oldbase)/name)],cwd=cwd,check=True)
    guard()
    shell='root="$1"; public="$2"; mode="$3"; hash="$4"; mount --bind "$public" "$root/work/t064-new-python"; mount -o remount,bind,ro "$root/work/t064-new-python"; for device in null zero urandom;do mount --bind "/dev/$device" "$root/dev/$device";done; chroot "$root" /usr/bin/env -i PATH=/opt/python/cp311-cp311/bin:/usr/bin:/bin PYTHONPATH=/work/t064-new-python PYTHONDONTWRITEBYTECODE=1 PEERWORK_TEST_EXPECTED_NATIVE_SHA256="$hash" /opt/python/cp311-cp311/bin/python -B /work/t064-installed-archive/consumer.py "$mode"'
    command=lambda mode:['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',shell,'t064-installed',str(oldroot),str(public),mode,native_sha]
    loader=subprocess.run(command('--loader'),capture_output=True,text=True,timeout=20);(logs/'loader.json').write_text(json.dumps(dict(exit_code=loader.returncode,stdout=loader.stdout,stderr=loader.stderr))+'\n');assert loader.returncode==0
    cmd=command('--consumer');(logs/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    server=work/'tests/lifecycle-origin-t063/server.mjs';argv=['/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node',str(server),'/root/workdir/message/.worktrees/e2ee-main-integration-20261006',str(case),str(logs/'command.json'),str(logs)]
    (logs/'invocation.json').write_text(json.dumps(dict(argv=argv,server_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),source=SOURCE,readonly_bind_public_only=str(public),same_case=str(case),data=str(data)),indent=2)+'\n')
    start=datetime.datetime.now(datetime.timezone.utc);t=time.monotonic()
    try:
        with(logs/'http.log').open('w')as out:r=subprocess.run(argv,stdout=out,stderr=subprocess.STDOUT,timeout=60)
        (logs/'terminal.json').write_text(json.dumps(dict(exit_code=r.returncode,start_utc=start.isoformat(),end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-t))+'\n')
    finally:guard()
    for name in ['inventory.json','first-read.json','negative.json','recovered-read.json','effects.json']:
        if (data/name).exists():shutil.copy2(data/name,logs/name)
    assert r.returncode==0
if __name__=='__main__':consume('--loader'in sys.argv)if'--consumer'in sys.argv or'--loader'in sys.argv else host()
