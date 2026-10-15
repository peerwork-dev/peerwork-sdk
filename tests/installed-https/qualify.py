"""Metadata-only loader qualification of the SAME partially prepared roots."""
from pathlib import Path
import importlib.util,os,subprocess,json,hashlib
W=Path(__file__).resolve().parents[2];E=W/'.test-data/t090';MAIN=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012');BASE=MAIN/'.build-artifacts/https-runtime-t090-20261015';HOME='/home/HTTPS offline 用户'
helper=MAIN/'tests/clean-gnu-runtime-t084.py';spec=importlib.util.spec_from_file_location('accepted_public_modes',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.HOME=HOME
rows=[]
for label in ['python','node','cli']:
 root=BASE/label;module.public_modes(root)
 def enter():
  os.chroot(root);os.chdir('/');os.setgroups([]);os.setgid(65534);os.setuid(65534);assert os.geteuid()==65534
  for p in ['/','/usr','/lib64','/lib64/ld-linux-x86-64.so.2']:assert os.access(p,os.X_OK)
  os.write(2,b'ACTUAL_EFFECTIVE_UID=65534 TRAVERSAL=PASS\n')
 r=subprocess.run(['/lib64/ld-linux-x86-64.so.2','--version'],preexec_fn=enter,capture_output=True,text=True,env={'PATH':'/usr/bin'})
 rows.append(dict(interface=label,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr,root_mode=oct(root.stat().st_mode&0o777),home_mode=oct((root/HOME.lstrip('/')).stat().st_mode&0o777)))
 assert r.returncode==0 and r.stderr=='ACTUAL_EFFECTIVE_UID=65534 TRAVERSAL=PASS\n'
(E/'qualification.json').write_text(json.dumps(dict(result='PASS',accepted_public_modes_source=str(helper),helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),calls=rows),indent=2)+'\n')
