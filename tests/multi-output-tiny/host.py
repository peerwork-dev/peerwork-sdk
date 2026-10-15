from pathlib import Path
import subprocess,json,time,datetime
W=Path(__file__).resolve().parents[2];E=W/'.test-data/t100';E.mkdir(parents=True,exist_ok=True);R=W/'.test-data/t100-runtime';N='/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node';REF='/root/workdir/message/.worktrees/e2ee-main-integration-20261006';script=W/'tests/multi-output-tiny/tiny.mjs'
# Mechanical syntax and source gates complete before the sole runtime creator runs.
subprocess.run([N,'--check',str(script)],check=True)
assert not R.exists()
argv=[N,str(script),REF,str(R)];(E/'invocation.json').write_text(json.dumps(argv)+'\n')
started=datetime.datetime.now(datetime.timezone.utc).isoformat();begin=time.monotonic()
with (E/'actual.stdout').open('wb') as out,(E/'actual.stderr').open('wb') as err:r=subprocess.run(argv,stdout=out,stderr=err,timeout=1050)
v={'exit_code':r.returncode,'started':started,'ended':datetime.datetime.now(datetime.timezone.utc).isoformat(),'seconds':time.monotonic()-begin,'runtime':str(R)};(E/'terminal.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v));raise SystemExit(r.returncode)
