import os,sys,json,hashlib,subprocess,sqlite3,platform
from pathlib import Path
import peerwork
from trace import traced_writer
assert platform.system()=='Linux'and platform.machine()=='x86_64'
SOURCE=Path(os.environ['PEERWORK_TEST_SDK_ROOT']);STATE=Path(os.environ['PEERWORK_TEST_STATE']);assert Path(peerwork.__file__).is_relative_to(SOURCE/'dist/python-consumer')
f=json.loads((STATE/'host-fixture.json').read_text());origin=f['origin'];native=STATE/'native';config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True);cf=STATE/'config.json';cf.write_text(json.dumps(config));cf.chmod(0o600)
owner=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True);identity=peerwork.import_legacy_owner_identity(str(cf),f['pem']);assert identity==f['identity']
created=owner.create('unrelated storage baseline','PRIVATE',structured=True);assert created['status']=='CREATED'and created['sequence']==1
baseline_read=owner.read(created['workspace_id']);target=native/'owner-create.state';identity_path=native/'identity.state';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();identity_hash=sha(identity_path)
CLI=os.environ['PEERWORK_TEST_CLI'];calls=[]
def cli(op,*args):
 r=subprocess.run([CLI,'secure','owner-'+op,str(cf),*args],capture_output=True,text=True,timeout=60)
 value=json.loads(r.stdout if r.returncode==0 else r.stderr);calls.append(dict(operation=op,exit_code=r.returncode,value=value));return r.returncode,value
def rows():
 with sqlite3.connect('file:'+str(STATE/'kernel/control.sqlite')+'?mode=ro',uri=True)as db:return db.execute('SELECT workspace_id,sequence,command_id,action_id,commit_hash FROM secure_commits ORDER BY workspace_id,sequence').fetchall()
def history():
 rc,value=cli('operations');assert rc==0;return value
records=[]
for phase in ['entry-kill','exit-kill','release']:
 before=history();before_hash=sha(target);before_inode=target.stat().st_ino;before_effects=rows()
 def boundary(pid,record):
  rc,value=cli('operations');assert rc==1 and value['code']=='LOCAL_STATE_FAILED',value
  assert sha(identity_path)==identity_hash and rows()==before_effects
  after_hash=sha(target)
  if record['phase']=='rename-entry':assert after_hash==before_hash and target.stat().st_ino==before_inode
  else:assert after_hash!=before_hash and target.stat().st_ino!=before_inode
  return dict(contending_cli='LOCAL_STATE_FAILED',identity_unchanged=True,workspace_effects_unchanged=True,target_sha256=after_hash,inode_replaced=target.stat().st_ino!=before_inode)
 result=traced_writer([sys.executable,str(Path(__file__).with_name('writer.py')),str(cf),phase],dict(os.environ),str(target),phase,STATE/(phase+'.stdout'),STATE/(phase+'.stderr'),boundary)
 assert result['boundary_reached']and result['exit_code']==(0 if phase=='release'else-9)
 after=history();assert sha(identity_path)==identity_hash and rows()==before_effects
 if phase=='entry-kill':assert after==before and sha(target)==before_hash
 else:
  old={r['command_id']:r for r in before};new=[r for r in after if r['command_id']not in old];assert len(new)==1 and new[0]['status']=='PENDING'
  assert all(r in after for r in before)
  if phase=='release':assert json.loads((STATE/(phase+'.stdout')).read_text())==new[0]
  command=new[0]['command_id'];rc,completed=cli('resume',command);assert rc==0 and completed['status']=='CREATED'and completed['sequence']==1
  rc,read=cli('read',completed['workspace_id']);assert rc==0 and read['sequence']==1 and read['head']==completed['head']and read['structure_status']=='ACTIVE'
  assert any(o['kind']=='workspaces'and o['id']==completed['workspace_id']and o['value']['owner']==identity['actor_id']and o['value']['visibility']=='PRIVATE'for o in read['objects'])
  effects=rows();assert len(effects)==len(before_effects)+1
  assert [r for r in effects if r[0]==completed['workspace_id']]==[(completed['workspace_id'],1,command,'secure.bootstrap',completed['head'])]
  rc,repeated=cli('resume',command);assert rc==0 and repeated==completed and rows()==effects
  result['recovered_original_command']=command;result['created_sequence']=1;result['repeat_no_effect']=True
 assert owner.read(created['workspace_id'])==baseline_read and sha(identity_path)==identity_hash
 result['identity_unchanged']=True;result['baseline_read_unchanged']=True;result['public_reopen_complete']=True;records.append(result)
path=STATE/'public-calls.json';path.write_text(json.dumps(calls,indent=2));path.chmod(0o600)
summary=dict(result='PASS',scope='native Linux x64 process interruption only; not power-loss/macOS/Windows',source='7dd319713708c417e5bc6026be1cf32ca598cfde',python_module=peerwork.__file__,cli=CLI,phases=records,final_service_commits=len(rows()),identity_unchanged=True)
(STATE/'effects.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
