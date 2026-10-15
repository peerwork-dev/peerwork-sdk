from pathlib import Path
import subprocess,json,time,datetime
W=Path(__file__).resolve().parents[2];H=Path(__file__).resolve().parent;E=W/'.test-data/t102';E.mkdir(parents=True,exist_ok=True);R=W/'.test-data/t102-private-fixture';N='/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node';REF='/root/workdir/message/.worktrees/e2ee-main-integration-20261006'
# Every syntax exit mechanically gates execution and the sole identity creator.
for p in H.glob('*.mjs'):subprocess.run([N,'--check',str(p)],check=True)
assert not R.exists()
commands={'order':[N,str(H/'order.mjs')],'identity':[N,str(H/'identity.mjs'),str(R),REF]}
(E/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
for name,argv in commands.items():
 began=datetime.datetime.now(datetime.timezone.utc).isoformat();start=time.monotonic()
 with (E/(name+'.stdout')).open('wb') as out,(E/(name+'.stderr')).open('wb') as err:r=subprocess.run(argv,stdout=out,stderr=err,timeout=20)
 v={'exit_code':r.returncode,'started':began,'ended':datetime.datetime.now(datetime.timezone.utc).isoformat(),'seconds':time.monotonic()-start};(E/(name+'.terminal.json')).write_text(json.dumps(v,indent=2)+'\n');assert r.returncode==0,(name,v)
assert json.loads((E/'order.stdout').read_text())['result']=='PASS';assert json.loads((E/'identity.stdout').read_text())['result']=='PASS';print(json.dumps({'result':'PASS','order_and_separate_process_signer_reopen':True,'http':False}))
