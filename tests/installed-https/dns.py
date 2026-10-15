"""A changed runtime-closure discriminator; no SDK/service calls."""
from pathlib import Path
import subprocess,json,shutil,hashlib,os
W=Path(__file__).resolve().parents[2];E=W/'.test-data/t090';MAIN=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012');BASE=MAIN/'.build-artifacts/https-runtime-t090-20261015';PUBLIC=MAIN/'.build-artifacts/transport-sdk-t089-20261015/rootfs/usr'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=(PUBLIC/'lib64/libnss_files.so.2').resolve();tool=PUBLIC/'bin/getent';rows=[]
for label in ['python','node','cli']:
 root=BASE/label;temporary=root/'usr/bin/getent';assert not temporary.exists();shutil.copyfile(tool,temporary);temporary.chmod(0o755)
 try:
  argv=['/usr/sbin/chroot','--userspec=65534:65534',str(root),'/usr/bin/getent','hosts','localhost']
  before=subprocess.run(argv,env={'PATH':'/usr/bin'},capture_output=True,text=True)
  destination=root/'lib64/libnss_files.so.2';assert not destination.exists();shutil.copyfile(source,destination);destination.chmod(0o755)
  after=subprocess.run(argv,env={'PATH':'/usr/bin'},capture_output=True,text=True)
  rows.append(dict(interface=label,argv=argv,before=dict(exit_code=before.returncode,stdout=before.stdout,stderr=before.stderr),after=dict(exit_code=after.returncode,stdout=after.stdout,stderr=after.stderr),source=str(source),source_sha256=sha(source),destination_sha256=sha(destination),temporary_getent_sha256=sha(temporary)))
  assert before.returncode!=0 and after.returncode==0 and 'localhost' in after.stdout
 finally:temporary.unlink()
(E/'dns-qualified.json').write_text(json.dumps(dict(result='PASS',calls=rows,only_added_runtime_library='libnss_files.so.2',temporary_getent_removed=True),indent=2)+'\n')
