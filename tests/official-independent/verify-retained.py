"""Check exact signed native outputs and service effects retained by the host."""
from pathlib import Path
import hashlib,json,sqlite3,sys
root=Path(sys.argv[1]);vector=json.loads(Path(sys.argv[2]).read_text());summaries=[]
for case in root.iterdir():
 if not(case/'calls.json').exists():continue
 calls=json.loads((case/'calls.json').read_text());values=[]
 for n,row in enumerate(calls):
  inp=json.loads((case/'calls'/f'{n:03d}.json').read_text());out=case/'calls'/f'{n:03d}.stdout';err=case/'calls'/f'{n:03d}.stderr'
  assert row['exit_code']==0 and hashlib.sha256(out.read_bytes()).hexdigest()==row['stdout_sha256'] and hashlib.sha256(err.read_bytes()).hexdigest()==row['stderr_sha256']
  values.append((inp,json.loads(out.read_text())))
 def one(op,command=None):return next(v for i,v in values if i['op']==op and(command is None or i['command']==command))
 owner=one('identity');local=one('recipient-create');assert owner['actor_id']!=local['actor_id']
 final=[v for i,v in values if i['op']=='owner-read'][-1];workspace=final['workspace_id'];instance='z'*43
 proposal=one('owner-status','p'*43);adoption=one('member-status','a'*43);task=one('owner-status','t'*43)
 for accepted,action,command,actor in [(proposal,'proposal.proposal.propose','p'*43,owner['actor_id']),(adoption,'proposal.proposal.adopt','a'*43,local['actor_id']),(task,'tasks.task.create_from_proposal','t'*43,owner['actor_id'])]:
  receipt=accepted['receipt'];assert accepted['status']=='ACCEPTED'and accepted['workspace_id']==workspace and accepted['command_id']==command and accepted['action_id']==action
  assert receipt['command_id']==command and receipt['action_id']==action and receipt['actor_id']==actor and receipt['instance_id']==instance and receipt['commit_hash']==accepted['commit_hash']and receipt['sequence']==accepted['sequence']
 candidate=proposal['receipt']['effects'][0]['record_id'];ref=dict(record_id=candidate,revision=1);taskid=task['receipt']['effects'][0]['record_id']
 candidate_row=next(o for o in final['objects']if o['kind']=='records'and o['id']==candidate);assert candidate_row['revision']==1 and candidate_row['value']['schema_ref']=='proposal.proposal.candidate'and candidate_row['value']['payload']['body']=='Exact adoption becomes a traceable task'
 protocol=next(o for o in final['objects']if o['kind']=='protocols'and o['id']==vector['protocol_digest']);assert protocol['value']['manifest']==vector['compiled_manifest']and protocol['value']['resolved_manifest']==vector['compiled_manifest']
 current=max([o for o in final['objects']if o['kind']=='instances'and o['id']==instance],key=lambda o:o['revision']);assert current['value']['state']['proposal']['adopted_ref']==ref and current['value']['state']['proposal']['adopted']is True
 tasks=[o for o in final['objects']if o['kind']=='records'and o['id']==taskid];assert len(tasks)==1 and tasks[0]['value']['payload']['assignee']==local['actor_id']and tasks[0]['value']['payload']['description']=='Implement adopted decision'
 with sqlite3.connect('file:'+str(case/'kernel/control.sqlite')+'?mode=ro',uri=True)as db:rows=db.execute('SELECT sequence,command_id,action_id,commit_hash,artifact FROM secure_commits WHERE workspace_id=? ORDER BY sequence',(workspace,)).fetchall()
 assert len(rows)==final['sequence']==7 and rows[-1][3]==final['head']==task['commit_hash']
 for command in ['p'*43,'a'*43,'t'*43]:assert sum(r[1]==command for r in rows)==1
 for row in rows:assert hashlib.sha256(row[4].encode()).hexdigest()==row[3]
 if case.name=='python-cli-handoff':
  submit=next((n,i,v)for n,(i,v)in enumerate(values)if i['op']=='owner-submit'and i['input']['command_id']=='p'*43);status=next((n,i,v)for n,(i,v)in enumerate(values)if i['op']=='owner-status'and i['command']=='p'*43)
  assert calls[submit[0]]['interface']=='python'and submit[2]['status']=='PENDING'and calls[status[0]]['interface']=='cli'and status[2]['status']=='ACCEPTED'and submit[1]['config']==status[1]['config']
 summaries.append(dict(case=case.name,result='PASS',commit_count=7,three_business_commands_once=True,receipt_tuples_bound=True,compiled_manifest_equal=True,exact_candidate_ref=ref,task_record_id=taskid,final_head=final['head'],handoff=(case.name=='python-cli-handoff')))
print(json.dumps(summaries,indent=2))
