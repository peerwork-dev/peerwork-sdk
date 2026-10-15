#!/usr/bin/env python3
"""Installed Owner UTF-16/TextEncoder name boundary, three fresh services; no Agent."""
from pathlib import Path
import os,sys,json,hashlib,subprocess,selectors,sqlite3,time,datetime
from urllib.parse import urlsplit
MAIN=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012');COHORT=MAIN/'.build-artifacts/archive-sdk-t064-20261015';ROOT=COHORT/'rootfs';GUEST='/work/sdk-config-t062-20261015';PIN='52a1f100ef735d25f237d2df2db796f0fd718ad0'
VALID=' '+'\ud800'*79+'  ';EXPECTED=[32]+[0xd800]*79+[32,32]
def consumer():
    import peerwork,peerwork._peerwork_native as ext
    os.umask(0o077);state=Path(os.environ['T067_CASE']);f=json.loads((state/'fixture.json').read_text());interface=f['interface'];origin=f['origin'];native=state/'native';native.mkdir(mode=0o700);config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True);cf=state/'config.json';cf.write_text(json.dumps(config));log=[]
    assert peerwork.__file__==GUEST+'/dist/python-consumer/peerwork/__init__.py' and ext.__file__==GUEST+'/dist/python-consumer/peerwork/_peerwork_native.abi3.so'
    pkg=GUEST+'/dist/node-consumer/node_modules/@peerwork/agent-sdk';node='/opt/node24/bin/node';cli=GUEST+'/target/release/peerwork';identity=native/'identity.state'
    def invoke(op,name=None,command=None,workspace=None):
        if interface=='python':
            try:
                o=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
                value=peerwork.create_identity(str(identity))if op=='identity-create' else peerwork.open_identity(str(identity))if op=='identity' else o.create(name,'PUBLIC',structured=False)if op=='create' else o.resume(command)if op=='resume' else o.read(workspace)if op=='read' else o.operations()
                result=dict(ok=True,value=value)
            except peerwork.OwnerWorkspaceError as e:result=dict(ok=False,code=e.code,message=str(e))
        elif interface=='node':
            js='''const fs=require('node:fs'),x=JSON.parse(fs.readFileSync(0,'utf8')),s=require(process.argv[1]);(async()=>{const o=s.openSecureOwnerWorkspaces({origin:x.origin,stateDir:x.state,allowLoopbackHttp:true});let v;if(x.op==='identity-create')v=await s.createIdentity(x.identity);else if(x.op==='identity')v=await s.openIdentity(x.identity);else if(x.op==='create')v=await o.create({name:x.name,visibility:'PUBLIC',structured:false});else if(x.op==='resume')v=await o.resume(x.command);else if(x.op==='read')v=await o.read(x.workspace);else v=await o.operations();console.log(JSON.stringify({ok:true,value:v}));})().catch(e=>console.log(JSON.stringify({ok:false,code:e.code,message:e.message})));'''
            r=subprocess.run([node,'-e',js,pkg],input=json.dumps(dict(op=op,origin=origin,state=str(native),identity=str(identity),name=name,command=command,workspace=workspace)),capture_output=True,text=True);assert r.returncode==0,r.stderr;result=json.loads(r.stdout)
        else:
            if op=='identity-create':args=['identity','create',str(identity)]
            elif op=='identity':args=['identity','info',str(identity)]
            elif op=='create':p=state/'input.json';p.write_text(json.dumps(dict(name=name,visibility='PUBLIC',structured=False)));args=['secure','owner-create',str(cf),str(p)]
            elif op=='resume':args=['secure','owner-resume',str(cf),command]
            elif op=='read':args=['secure','owner-read',str(cf),workspace]
            else:args=['secure','owner-operations',str(cf)]
            r=subprocess.run([cli,*args],capture_output=True,text=True);result=dict(ok=True,value=json.loads(r.stdout))if r.returncode==0 else dict(ok=False,**json.loads(r.stderr));assert not r.stderr if r.returncode==0 else not r.stdout
        log.append(dict(operation=op,name_units=None if name is None else[ord(x)for x in name],result=result));(state/'calls.json').write_text(json.dumps(log,indent=2)+'\n');return result
    def good(op,**kw):r=invoke(op,**kw);assert r['ok'],r;return r['value']
    def rows(q,args=()):
        with sqlite3.connect('file:'+str(state/'service/control.sqlite')+'?mode=ro',uri=True)as db:return db.execute(q,args).fetchall()
    def requests():return[r for line in(state/'requests.jsonl').read_text().splitlines()if(r:=json.loads(line))['host']==urlsplit(origin).netloc]
    public=good('identity-create');assert good('identity')==public and good('operations')==[];baseline=sorted(p.name for p in native.iterdir())
    assert rows('select count(*) from secure_workspaces')==[(0,)]and rows('select count(*) from secure_commits')==[(0,)]and requests()==[]
    for bad in ['',VALID+'x']:
        r=invoke('create',name=bad);assert r['ok']is False and r['code']=='INPUT_INVALID';assert good('operations')==[]and sorted(p.name for p in native.iterdir())==baseline
        assert rows('select count(*) from secure_workspaces')==[(0,)]and rows('select count(*) from secure_commits')==[(0,)]and requests()==[]
    created=good('create',name=VALID);assert created['status']=='CREATED'and created['sequence']==1;command=created['command_id'];workspace=created['workspace_id']
    read=good('read',workspace=workspace);assert read['sequence']==1 and read['head']==created['head']and read['workspace_id']==workspace and read['structure_status']=='UNSTRUCTURED'
    spaces=[o for o in read['objects']if o['kind']=='workspaces'];assert len(spaces)==1 and spaces[0]['id']==workspace and [ord(x)for x in spaces[0]['value']['name']]==EXPECTED and spaces[0]['value']['owner']==public['actor_id']
    commits=rows('select command_id,commit_hash,policy_hash,artifact from secure_commits where workspace_id=?',(workspace,));assert len(commits)==1;row=commits[0];assert row[0]==command and row[1]==read['head']and row[2]==read['policy_hash']and hashlib.sha256(row[3].encode()).hexdigest()==row[1]
    artifact=state/'signed-bootstrap.json';artifact.write_text(row[3]);rf=state/'verified-read.json';rf.write_text(json.dumps(read));
    oracle=r'''const fs=require('node:fs'),a=JSON.parse(fs.readFileSync(process.argv[1],'utf8')),r=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));const expected=[32,...Array(79).fill(0xd800),32,32],units=s=>Array.from({length:s.length},(_,i)=>s.charCodeAt(i));const name=' '+'\ud800'.repeat(79)+'  ';const b=a.payload.body.objects.filter(o=>o.kind==='workspaces')[0].value.name,v=r.objects.filter(o=>o.kind==='workspaces')[0].value.name;for(const s of[b,v]){if(JSON.stringify(units(s))!==JSON.stringify(expected)||new TextEncoder().encode(s).byteLength!==240)throw Error('UTF16/byte mismatch');}console.log(JSON.stringify({artifact_units:units(b),verified_read_units:units(v),textencoder_bytes:new TextEncoder().encode(v).byteLength,unchanged_spaces:true,no_replacement_units:!units(v).includes(0xfffd)}));'''
    oracle_run=subprocess.run([node,'-e',oracle,str(artifact),str(rf)],capture_output=True,text=True);assert oracle_run.returncode==0,oracle_run.stderr;oracle_value=json.loads(oracle_run.stdout);(state/'ts-oracle.json').write_text(json.dumps(oracle_value,indent=2)+'\n')
    policy=rows('select artifact from secure_policies where workspace_id=?and policy_hash=?',(workspace,read['policy_hash']));assert len(policy)==1;body='{"commit":'+row[3]+',"policy":'+policy[0][0]+'}';req=requests();assert len(req)==1 and req[0]['command_id']==command and req[0]['method']=='POST'and req[0]['path']=='/api/workspace/v1/secure/workspaces'and req[0]['body_sha256']==hashlib.sha256(body.encode()).hexdigest()
    assert good('resume',command=command)==created and good('read',workspace=workspace)==read and good('identity')==public and requests()==req and rows('select count(*)from secure_workspaces')==[(1,)]and rows('select count(*)from secure_commits')==[(1,)]
    result=dict(result='PASS',interface=interface,source=PIN,name_utf16_units=82,textencoder_bytes=240,leading_spaces=1,trailing_spaces=2,lone_high_surrogates=79,empty_and_241_refused_before_create=True,bootstrap_posts=1,workspaces=1,commits=1,signed_sequence=1,original_command_resume_idempotent=True,identity_continuity=True,ts_oracle=oracle_value)
    (state/'effects.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
def host():
    os.umask(0o077);root=ROOT.resolve();sdk=root/GUEST.lstrip('/');work=Path(__file__).resolve().parents[1];logs=work/'.test-data/t067';logs.mkdir(parents=True,mode=0o700,exist_ok=True);assert not(logs/'terminal-cases.json').exists();task=root/'work/t067-owner-names-first';task.mkdir(mode=0o700);runner=task/'consumer.py';runner.write_bytes(Path(__file__).read_bytes());reference='/root/workdir/message/.worktrees/e2ee-main-integration-20261006';node='/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node'
    def guard():
        assert hashlib.sha256((COHORT/'artifact-manifest.sha256').read_bytes()).hexdigest()=='d545bf69b2f84267e777316b0851bd2b2462be6f455f85accc9021de96500868'
        for f,cwd in [('artifact-manifest.sha256',COHORT),('source-manifest-final.sha256',sdk)]:subprocess.run(['sha256sum','-c','--status',str(COHORT/f)],cwd=cwd,check=True)
    guard();results=[]
    for interface in ['python','node','cli']:
        case=task/interface;case.mkdir(mode=0o700);service=case/'service';service.mkdir(mode=0o700);(case/'requests.jsonl').touch(mode=0o600);stderr=(service/'stderr.log').open('w');process=None
        try:
            env=dict(os.environ,PEERWORK_REFERENCE_ROOT=reference,PEERWORK_TEST_STATE=str(service),PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(case/'requests.jsonl'))
            argv=[node,'--require',str(sdk/'tests/installed-coordination-genesis/request-observer.cjs'),str(sdk/'tests/reference-kernel-server.mjs')];process=subprocess.Popen(argv,env=env,stdout=subprocess.PIPE,stderr=stderr,text=True);sel=selectors.DefaultSelector();sel.register(process.stdout,selectors.EVENT_READ);assert sel.select(30),'READY timeout';ready=json.loads(process.stdout.readline());sel.close();(service/'ready.json').write_text(json.dumps(ready));(case/'fixture.json').write_text(json.dumps(dict(interface=interface,origin=ready['origin'])))
            shell='root="$1";case="$2";for d in null zero urandom;do mount --bind "/dev/$d" "$root/dev/$d";done;chroot "$root" /usr/bin/env -i PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/bin:/bin PYTHONPATH=/work/sdk-config-t062-20261015/dist/python-consumer PYTHONDONTWRITEBYTECODE=1 T067_CASE="$case" /opt/python/cp311-cp311/bin/python -B /work/t067-owner-names-first/consumer.py --consumer'
            cmd=['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',shell,'t067',str(root),'/work/t067-owner-names-first/'+interface];(case/'invocation.json').write_text(json.dumps(cmd,indent=2));t=time.monotonic();start=datetime.datetime.now(datetime.timezone.utc);r=subprocess.run(cmd,capture_output=True,text=True,timeout=120);(case/'consumer.stdout').write_text(r.stdout);(case/'consumer.stderr').write_text(r.stderr);row=dict(interface=interface,exit_code=r.returncode,seconds=time.monotonic()-t,start_utc=start.isoformat(),end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());results.append(row);print(json.dumps(row),flush=True)
            assert r.returncode==0,'preserved first consumer failure; stop before subsequent cases'
        finally:
            if process is not None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
                (service/'exit.json').write_text(json.dumps(dict(pid=process.pid,exit_code=process.returncode)))
            stderr.close();guard();(logs/'terminal-cases.json').write_text(json.dumps(results,indent=2)+'\n')
    (logs/'result-path.json').write_text(json.dumps(dict(state=str(task),source=PIN,interfaces=results),indent=2)+'\n')
if __name__=='__main__':consumer()if'--consumer'in sys.argv else host()
