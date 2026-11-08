import json,os,sys,tempfile
from pathlib import Path
from trace import run_child
HERE=Path(__file__).resolve().parent
results={}
with tempfile.TemporaryDirectory(prefix='t093-control-') as temporary:
 for mode in ['positive','wrong-backup','prearm-headers','short-payload','missing-close']:
  root=Path(temporary)/mode;root.mkdir(mode=0o700);backup=root/'backup';backup.write_bytes(b'public qualification');wal=root/'native-wal'
  holds=[]
  def hold(pid,events):
   assert wal.stat().st_size==56
   os.kill(pid,0);holds.append({'pid':pid,'wal_size_while_stopped':56,'released':True})
  selected=backup if mode!='wrong-backup' else root/'other'
  result=run_child([sys.executable,str(HERE/'dummy.py'),str(backup),str(wal),mode],dict(os.environ),str(selected),str(wal),True,on_hold=hold)
  assert result['exit_code']==0 and result['boundary_reached']==(mode=='positive')
  assert len(holds)==int(mode=='positive')
  assert wal.stat().st_size==(567 if mode=='short-payload' else 568)
  results[mode]={'trace':result,'holds':holds}
print(json.dumps({'result':'PASS','cases':results,'buffers_read':False}))
