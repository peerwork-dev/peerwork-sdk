import os,sys,json,hashlib,time,subprocess,datetime
from pathlib import Path
import peerwork,peerwork._peerwork_native as native
from trace import run_child
S=Path(os.environ['T093_SOURCE']);R=Path(os.environ['T093_RUNTIME']);SDK=Path(os.environ['T093_SDK']);F=json.loads((S/'fixture.json').read_text())
source=S/'legacy.sqlite';backup=S/'checked-backup.sqlite';identity=S/'native-identity.state';journal=R/'native-journal.sqlite';cli=SDK/'target/release/peerwork'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(name,value):
 p=R/name;p.write_text(json.dumps(value,sort_keys=True)+'\n');p.chmod(0o600)
def client():return peerwork.KernelClient(F['origin'],str(journal),str(identity),allow_loopback_http=True)
assert Path(peerwork.__file__)==SDK/'dist/python-consumer/peerwork/__init__.py'
if '--writer' in sys.argv:
 report=client().migrate_ts_store(str(source),str(backup),[F['key_id']]);save('writer-result.json',report);print(json.dumps(report),flush=True);raise SystemExit(0)
assert not R.exists();R.mkdir(mode=0o700)
public=peerwork.open_identity(str(identity));assert public['actor_id']==F['actor_id'] and public['key_id']==F['key_id']
meta=lambda p:[p.stat().st_ino,p.stat().st_size,p.stat().st_mtime_ns]
before={'source_sha256':sha(source),'backup_sha256':sha(backup),'identity_metadata':meta(identity),'public_identity':public,'python':sys.version,'wrapper':str(peerwork.__file__),'native':str(native.__file__),'native_sha256':sha(Path(native.__file__)),'cli_sha256':sha(cli)};save('before.json',before)
assert client().pending()==[]
assert client().status(F['accepted_id'])=={'state':'NOT_FOUND'} and client().status(F['pending_id'])=={'state':'NOT_FOUND'}
base=[str(cli),'kernel','migrate',F['origin'],str(journal),str(identity),str(source),str(backup),'--trusted-signer='+F['key_id'],'--allow-loopback-http']
held=[]
def on_hold(pid,events):
 started=datetime.datetime.now(datetime.timezone.utc).isoformat();begin=time.monotonic();os.kill(pid,0)
 with (R/'contender.stdout').open('wb') as out,(R/'contender.stderr').open('wb') as err:
  saved_out=os.dup(1);saved_err=os.dup(2)
  try:
   os.dup2(out.fileno(),1);os.dup2(err.fileno(),2)
   observed=run_child(base,dict(os.environ),str(backup),str(journal)+'-wal',False,timeout=15)
  finally:os.dup2(saved_out,1);os.dup2(saved_err,2);os.close(saved_out);os.close(saved_err)
  save('contender-lock-trace.json',observed)
 terminal={'argv':base,'pid_of_stopped_writer':pid,'writer_still_stopped':True,'exit_code':observed['exit_code'],'started':started,'seconds':time.monotonic()-begin,'ended':datetime.datetime.now(datetime.timezone.utc).isoformat()};save('contender-terminal.json',terminal)
 os.kill(pid,0);held.append(terminal)
 assert observed['exit_code']!=0,'contender unexpectedly completed while exact destination writer held'
 message=(R/'contender.stderr').read_text()+(R/'contender.stdout').read_text()
 assert any(e.get('syscall')=='fcntl' and e.get('exact_destination_lock_file') and e.get('command')==6 and e.get('return') in [-11,-13] for e in observed['events']),'no observed exact destination nonblocking lock refusal; preserve first public output'
with (R/'writer.stdout').open('wb') as out,(R/'writer.stderr').open('wb') as err:
 # Traced child inherits these output descriptors; callback contender owns separate files.
 saved_out=os.dup(1);saved_err=os.dup(2)
 try:
  os.dup2(out.fileno(),1);os.dup2(err.fileno(),2)
  trace=run_child([sys.executable,__file__,'--writer'],dict(os.environ),str(backup),str(journal)+'-wal',True,timeout=35,on_hold=on_hold)
 finally:os.dup2(saved_out,1);os.dup2(saved_err,2);os.close(saved_out);os.close(saved_err)
save('trace-result.json',trace)
assert trace['exit_code']==0 and trace['boundary_reached'] and trace['armed_by_backup_close'] and len(held)==1
assert not any(e.get('phase')=='entry' and e.get('syscall')=='pwrite64' and e.get('exact_wal') and not e.get('armed') for e in trace['events'])
assert json.loads((R/'writer-result.json').read_text())=={'pending_count':1,'accepted_count':1}
with (R/'retry.stdout').open('wb') as out,(R/'retry.stderr').open('wb') as err:retry=subprocess.run(base,stdout=out,stderr=err,timeout=12,env=dict(os.environ))
save('retry-terminal.json',{'exit_code':retry.returncode,'argv':base});assert retry.returncode==0
retry_value=json.loads((R/'retry.stdout').read_text());assert retry_value=={'pending_count':1,'accepted_count':1},retry_value
accepted=client().status(F['accepted_id']);pending=client().pending();assert accepted['state']=='ACCEPTED' and accepted['result']['command_id']==F['accepted_id'] and accepted['result']['workspace_id']==F['accepted_workspace_id']
assert client().status(F['pending_id'])=={'state':'PENDING'} and len(pending)==1 and pending[0]['command_id']==F['pending_id'] and pending[0]['intent_digest']==F['pending_digest']
assert client().migrate_ts_store(str(source),str(backup),[F['key_id']])==retry_value
assert client().status(F['accepted_id'])==accepted and client().pending()==pending
assert sha(source)==before['source_sha256'] and sha(backup)==before['backup_sha256'] and meta(identity)==before['identity_metadata'] and peerwork.open_identity(str(identity))==public
assert backup.stat().st_mode&0o077==0
save('result.json',{'result':'PASS','trace':trace,'contender':held[0],'retry':retry_value,'accepted':accepted,'pending':pending,'source_backup_unchanged':True,'identity_unchanged':True,'fresh_handles':True,'no_submit_calls':True})
print(json.dumps({'result':'PASS','contender_exit':held[0]['exit_code'],'retry':retry_value,'writer_exit':trace['exit_code']}),flush=True)
