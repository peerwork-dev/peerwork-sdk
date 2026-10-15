#!/usr/bin/env python3
"""One fresh no-model CLI route/input regression; no Actor or installed cohort rebuild."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import subprocess
import sys

if len(sys.argv) != 4:
    raise SystemExit('usage: private-install-cli-guidance.py CLI CLI_SHA256 NEW_PROTECTED_DIRECTORY')
os.umask(0o077)
cli = Path(sys.argv[1]).resolve(strict=True)
expected_cli_hash = sys.argv[2]
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert sha(cli) == expected_cli_hash
source = Path(__file__).resolve().parents[1]
reference = source.parent / 'e2ee-main-integration-20261006'
node = Path('/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node')
task = Path(sys.argv[3]).absolute()
assert not task.exists() and task.parent.is_dir() and not task.parent.is_symlink()
task.mkdir(mode=0o700)
operator = task / 'operator'; operator.mkdir(mode=0o700)
selected = task / 'selected'; selected.mkdir(mode=0o700)

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n'); path.chmod(0o600)

def call(label, *args, code=None):
    result = subprocess.run([str(cli), *args], capture_output=True, timeout=90,
        env={k:v for k,v in os.environ.items() if k not in ('PEERWORK_HTTP_PROXY',)})
    for suffix, data in [('stdout',result.stdout),('stderr',result.stderr)]:
        p=operator/f'{label}.{suffix}'; p.write_bytes(data); p.chmod(0o600)
    save(operator/f'{label}.process.json', {'returncode':result.returncode,
        'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),
        'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()})
    if code:
        assert result.returncode != 0, label
        error=json.loads(result.stderr); assert error['code']==code, (label,error['code'])
        return error
    assert result.returncode == 0, (label,result.returncode)
    return json.loads(result.stdout)

help_verbs=['owner-private-install-begin-direct','owner-private-install-begin',
    'owner-private-stage-submit','owner-private-stage-continue','owner-private-stage-list',
    'owner-private-install-continue','owner-private-install-list','owner-install-pending',
    'owner-private-action-submit','owner-private-action-pending','owner-private-action-status','owner-private-action-retry']
helps={verb:call('help-'+verb,'secure',verb,'--help') for verb in help_verbs}
assert all(row['status']=='HELP' and row['command']==verb for verb,row in helps.items())
assert helps['owner-install-pending']['workspace_visibility']=='PUBLIC'
assert all(helps[v]['workspace_visibility']=='PRIVATE' for v in help_verbs if v!='owner-install-pending')
assert helps['owner-private-install-begin']['input_example']['stage_id']
assert helps['owner-private-stage-submit']['input_example']['material_json']
assert not (task/'native-state').exists()  # help does not require/create an identity/config
caps=call('capabilities','capabilities')
authored=subprocess.run([str(node),str(source/'tests/agent-trial/author_wiki_material.mjs'),str(reference),str(selected)],capture_output=True,timeout=60)
save(operator/'author-process.json',{'returncode':authored.returncode,'stdout':authored.stdout.decode(),'stderr':authored.stderr.decode()})
assert authored.returncode==0
proof=json.loads(authored.stdout)
pem=selected/'owner.pem'
subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(pem)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
pem.chmod(0o400)
service=task/'service';service.mkdir(mode=0o700)
server=subprocess.Popen([str(node),str(source/'tests/reference-kernel-server.mjs')],cwd=source,
    env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(reference),PEERWORK_TEST_STATE=str(service),PEERWORK_TEST_FIRST_POST_MODE='normal'),
    stdout=subprocess.PIPE,stderr=(operator/'service.stderr').open('wb'))
try:
    ready=server.stdout.readline(); assert ready, 'reference server readiness'
    origin=json.loads(ready)['origin']
    config=task/'config.json';save(config,{'origin':origin,'state_dir':str(task/'native-state'),'allow_loopback_http':True})
    imported=call('import','identity','import-legacy-owner-pem',str(config),str(pem))
    identity=call('identity-info','identity','info',str(task/'native-state/identity.state'))
    assert all(isinstance(identity.get(k),str) and identity[k] and identity[k]==imported.get(k) for k in ('actor_id','key_id'))
    create=task/'create.json';save(create,{'name':'PRIVATE route regression','visibility':'PRIVATE','structured':True})
    created=call('create','secure','owner-create',str(config),str(create))
    assert created['status']=='CREATED' and created['visibility']=='PRIVATE'
    workspace=created['workspace_id']
    before=call('read-before','secure','owner-read',str(config),workspace)
    db=sqlite3.connect(f'file:{service/"control.sqlite"}?mode=ro',uri=True)
    def count(): return db.execute('select count(*) from secure_commits where workspace_id=?',(workspace,)).fetchone()[0]
    initial_count=count(); assert initial_count==before['sequence']==1
    public_error=call('public-route','secure','owner-install-pending',str(config),workspace,code='NOT_FOUND')
    assert 'PUBLIC only' in public_error['message'] and 'owner-private-install-list' in public_error['message']
    assert call('private-install-empty','secure','owner-private-install-list',str(config),workspace)==[]
    assert call('private-stage-empty','secure','owner-private-stage-list',str(config),workspace)==[]
    material=selected/'material.json'
    for verb in ('owner-private-install-begin','owner-private-install-begin-direct','owner-private-stage-submit'):
        error=call('raw-material-'+verb,'secure',verb,str(config),workspace,str(material),code='INSTALL_INPUT_INVALID')
        assert 'raw material' in error['message'].lower() and '--help' in error['message']
    assert count()==initial_count
    assert call('private-install-still-empty','secure','owner-private-install-list',str(config),workspace)==[]
    assert call('private-stage-still-empty','secure','owner-private-stage-list',str(config),workspace)==[]
    instance=secrets.token_urlsafe(32)
    # Exactly the documented/help direct envelope, with explicit compiler pins and grants.
    install={**helps['owner-private-install-begin-direct']['input_example'],
        'closure_json':json.dumps(json.loads((selected/'closure.json').read_text()),separators=(',',':')),
        'expected_root_package_digest':proof['root_package_digest'],'expected_protocol_digest':proof['protocol_digest'],
        'instance_id':instance,'entrypoint':'wiki',
        'grants_json':json.dumps([{'actor_id':identity['actor_id'],'actions':['wiki.create'],'protocol_roles':['EDITOR'],'capabilities':['EDIT']}],separators=(',',':'))}
    direct=task/'direct.json';save(direct,install)
    progress=call('direct-begin','secure','owner-private-install-begin-direct',str(config),workspace,str(direct))
    begin=progress['begin_command_id']
    for step in range(8):
        if progress['status']=='ACCEPTED': break
        assert progress['status']=='PENDING'
        progress=call(f'direct-continue-{step}','secure','owner-private-install-continue',str(config),workspace,begin)
    assert progress['status']=='ACCEPTED' and progress['instance_id']==instance
    read=call('read-installed','secure','owner-read',str(config),workspace)
    assert read['workspace_id']==workspace and read['structure_status']=='ACTIVE' and read['sequence']==3
    def selected_instances(read):
        rows=[o for o in read['objects'] if o['kind']=='instances' and o['id']==instance]
        assert rows
        assert {o['id'] for o in rows}=={instance}
        assert all(o['value']['protocol_digest']==proof['protocol_digest'] and o['value']['origin_entrypoint']=='wiki' for o in rows)
    selected_instances(read)
    assert call('private-action-empty','secure','owner-private-action-pending',str(config),workspace)==[]
    command=secrets.token_urlsafe(32); title='CLI route regression'; body='One explicitly authorized PRIVATE action.'
    action=task/'action.json';save(action,{'action_id':'wiki.create','instance_id':instance,'body_json':json.dumps({'title':title,'body':body}),'command_id':command})
    result=call('private-action-submit','secure','owner-private-action-submit',str(config),workspace,str(action))
    result=call('private-action-status','secure','owner-private-action-status',str(config),workspace,command)
    assert result['status']=='ACCEPTED' and result['workspace_id']==workspace and result['command_id']==command and result['action_id']=='wiki.create' and result['sequence']==4
    receipt=result['receipt']; assert receipt['instance_id']==instance and receipt['actor_id']==identity['actor_id'] and receipt['command_id']==command and receipt['commit_hash']==result['commit_hash'] and receipt['sequence']==4
    retried=call('private-action-retry','secure','owner-private-action-retry',str(config),workspace,command)
    assert retried==result and count()==4
    after=call('read-final','secure','owner-read',str(config),workspace)
    assert after['workspace_id']==workspace and after['structure_status']=='ACTIVE' and after['sequence']==4
    selected_instances(after)
    ws=[o for o in after['objects'] if o['kind']=='workspaces' and o['id']==workspace]
    assert len(ws)==1 and ws[0]['value']['visibility']=='PRIVATE' and ws[0]['value']['owner']==identity['actor_id']
    notes=[o for o in after['objects'] if o['kind']=='records' and o['value'].get('instance_id')==instance and o['value'].get('protocol_digest')==proof['protocol_digest'] and o['value'].get('schema_ref')=='wiki.revision' and o['value'].get('payload',{}).get('title')==title and o['value'].get('payload',{}).get('body')==body and o['value'].get('payload',{}).get('author')==identity['actor_id']]
    assert len(notes)==1 and len(receipt['effects'])==1 and receipt['effects'][0]['record_id']==notes[0]['id'] and receipt['effects'][0]['schema_ref']=='wiki.revision'
    assert db.execute('select count(*) from secure_commits where workspace_id=? and command_id=? and action_id=?',(workspace,command,'wiki.create')).fetchone()[0]==1
    db.close()
    summary={'status':'PASS','cli_sha256':sha(cli),'help_commands':len(helps),'identity_bound':True,'visibility_route_hint':True,'three_raw_material_refusals_no_commits':True,'help_shaped_direct_install_accepted':True,'private_action_status_retry_receipt_readback':True,'selected_author_package':proof['protocol_digest'],'sequence_before':1,'sequence_installed':3,'sequence_final':4,'accepted_commits':4,'no_actor':True}
    save(operator/'summary.json',summary)
finally:
    server.send_signal(signal.SIGTERM)
    try: server.wait(timeout=10)
    except subprocess.TimeoutExpired: server.kill();server.wait()
    save(operator/'service-process.json',{'returncode':server.returncode,'stderr_sha256':sha(operator/'service.stderr')})
assert sha(cli)==expected_cli_hash
print(json.dumps(summary,separators=(',',':')))
