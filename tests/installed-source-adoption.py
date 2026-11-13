#!/usr/bin/env python3
"""Qualify an installed client against an original runtime using synthetic HTTP only."""
import argparse,hashlib,json,os,queue,subprocess,tempfile,threading,time,urllib.request
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli',required=True,type=Path)
    parser.add_argument('--original-cli',required=True,type=Path)
    parser.add_argument('--product-root',required=True,type=Path)
    args=parser.parse_args();cli=args.cli.resolve();original=args.original_cli.resolve();product=args.product_root.resolve()
    assert os.environ.get('PEERWORK_POSTGRES_TEST_URL'),'explicit synthetic PostgreSQL required'
    processes=[];runtime=None;ready=None;service=None
    with tempfile.TemporaryDirectory(prefix='peerwork original source ') as temporary:
        root=Path(temporary).resolve();root.chmod(0o700)
        env=dict(os.environ,XDG_STATE_HOME=str(root/'user-state'),PEERWORK_STRUCTURE_REFERENCE_ROOT=str(product))
        def write(name,value):
            path=root/name;path.write_text(json.dumps(value));path.chmod(0o600);return path
        def run(*words,success=True,binary=cli,timeout=30):
            result=subprocess.run([str(binary),*map(str,words)],cwd=root,env=env,text=True,capture_output=True,timeout=timeout)
            value=json.loads(result.stdout)
            assert (result.returncode==0)==success,{'returncode':result.returncode,'result':value,'stderr':result.stderr[-1000:]}
            return value
        def line(process):
            messages=queue.Queue(maxsize=1);threading.Thread(target=lambda:messages.put(process.stdout.readline()),daemon=True).start()
            raw=messages.get(timeout=30);assert raw,'synthetic process did not become ready';return json.loads(raw)
        def call(endpoint,request):
            response=run('runtime','call',endpoint,write('request.json',request));assert response['ok'],response;return response['value']
        def start():
            child=subprocess.Popen([str(original),'runtime','run',str(config_path)],cwd=root,env=env,text=True,stdout=subprocess.PIPE,stderr=(root/'runtime.log').open('a'))
            processes.append(child);value=line(child);assert value['state']=='LOCAL_READY',value;return child,value
        def stop():
            nonlocal runtime
            if ready:
                result=subprocess.run([str(cli),'runtime','admin',str(ready['admin_endpoint']),'stop'],cwd=root,env=env,text=True,capture_output=True,timeout=15)
                assert result.returncode==0,result.stdout+result.stderr
            if runtime:runtime.wait(timeout=20)
            runtime=None
        def invoke(endpoint,id,action,scope,body,workspace_revision=None):
            request={'operation_id':id,'action':action,'scope':scope,'body':body}
            if workspace_revision is not None:request['expected_workspace_revision']=workspace_revision
            result=call(endpoint,{'method':'invoke','request':request,'wait_ms':5000})
            end=time.monotonic()+20
            while result['state']=='PENDING' and time.monotonic()<end:result=call(endpoint,{'method':'recover','operation_id':id})
            assert result['state']=='ACCEPTED',result;return result
        def mcp_observe(profile):
            process=subprocess.Popen([str(cli),'agent','--profile',str(profile),'mcp'],cwd=root,env=env,text=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(root/'mcp.log').open('a'));processes.append(process)
            def rpc(id,method,params):
                process.stdin.write(json.dumps({'jsonrpc':'2.0','id':id,'method':method,'params':params})+'\n');process.stdin.flush()
                response=line(process);assert response['id']==id and 'error' not in response,response;return response['result']
            try:
                rpc(1,'initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'original-source-qualification','version':'1'}})
                process.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');process.stdin.flush()
                listed=rpc(2,'tools/list',{});assert {'peerwork_context','peerwork_connect','peerwork_reachability'}.issubset({tool['name']for tool in listed['tools']})
                response=rpc(3,'tools/call',{'name':'peerwork_reachability','arguments':{}});result=response['structuredContent'];assert len(result['members'])==1,result
                response=rpc(4,'tools/call',{'name':'peerwork_status','arguments':{'operation_id':'original-name'}});result=response['structuredContent'];assert result['command_id']==command_id,result
                return result['command_id']
            finally:
                process.stdin.close();process.wait(timeout=20);assert process.returncode==0
        try:
            service=subprocess.Popen([env.get('PEERWORK_TEST_NODE','node'),str(Path(__file__).resolve().parent/'participant-service.mjs')],cwd=root,env=env,text=True,stdout=subprocess.PIPE,stderr=(root/'service.log').open('a'));processes.append(service)
            origin=line(service)['origin'];identity=root/'identity.state';created=run('identity','create',identity)
            # Fixture setup uses an original full client, then freezes the actual
            # tested original client with the restrictive old configuration.
            capability={'operations':['structure.workspace.create','structure.workspace.get','structure.member.name.set','structure.members.read'],'allow_root':True,'workspace_ids':None,'instance_ids':None,'protocol_digests':None,'business_actions':None}
            config={'format':'peerwork.participant-runtime.v1','state_directory':str(root/'runtime'),'hosts':[],
                'engines':[{'name':'original','origin':origin,'expected_actor':created['actor_id'],'identity_path':str(identity),'state_directory':str(root/'engine'),'journal_path':str(root/'journal.sqlite'),'allow_loopback_http':True,'transport':{'request_timeout_ms':10000},'max_inflight':4,'max_pending':16}],
                'clients':[{'name':'root','engine':'original','capability':capability}]}
            config_path=write('original-runtime.json',config);runtime,ready=start();endpoint=ready['client_endpoints']['root']
            result=invoke(endpoint,'fixture-space','structure.workspace.create',{}, {'name':'Installed old source'})
            workspace=result['outcome']['result']['structure']['workspace_id'];stop()
            capability['allow_root']=False;capability['workspace_ids']=[workspace];capability['operations'].remove('structure.workspace.create');capability['operations'].remove('structure.members.read')
            config_path=write('original-runtime.json',config);runtime,ready=start();endpoint=ready['client_endpoints']['root']
            scope={'workspace_id':workspace}
            current=call(endpoint,{'method':'request','request':{'operation_id':'current','action':'structure.workspace.get','scope':scope,'body':{}}})['result']['structure']
            saved=invoke(endpoint,'original-name','structure.member.name.set',scope,{'membership_id':current['membership']['membership_id'],'name':'Original Root'},current['workspace_revision']);command_id=saved['command_id']
            profile=write('agent-mcp033.json',{'format':'peerwork.agent-profile.v1','expected_origin':origin,'expected_actor':created['actor_id'],'endpoint_path':endpoint,'workspaces':{'project':workspace},'scopes':{}})
            hashes={str(path):hashlib.sha256(path.read_bytes()).hexdigest()for path in [identity,config_path,profile]}
            denied=run('agent','--profile',profile,'reachability',success=False);assert denied['error']['code'] in ['LOCAL_SCOPE_DENIED','LOCAL_RUNTIME_UPGRADE_REQUIRED'],denied
            adopted=run('connect','--profile',profile,'--runtime-config',config_path,'--adopt-policy','inherit-engine',timeout=90)
            assert adopted['state'] in ['LOCAL_PROFILE_ADOPTED','LOCAL_READY','LOCAL_ATTACHED','LOCAL_CONFIGURED','PROFILE_ADOPTED'],adopted
            runtime.wait(timeout=20);runtime=None
            page=run('agent','--profile',profile,'reachability');assert len(page['members'])==1 and page['members'][0]['actor_id']==created['actor_id'],page
            # Two independent MCP frontends continue using the unchanged source.
            assert mcp_observe(profile)==mcp_observe(profile)==command_id
            repeated=run('connect','--profile',profile,'--runtime-config',config_path,'--adopt-policy','inherit-engine',timeout=90);assert repeated['state']==adopted['state'],repeated
            with urllib.request.urlopen(urllib.request.Request(origin+'/__test/config',data=json.dumps({'offline':True}).encode(),headers={'Content-Type':'application/json'}),timeout=10) as response:assert response.status==200
            status=run('agent','--profile',profile,'status','original-name');assert status['command_id']==command_id,status
            recovered=run('agent','--profile',profile,'recover','original-name');assert recovered['command_id']==command_id,recovered
            assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest for path,digest in hashes.items())
            original_caps=call(endpoint,{'method':'capabilities'});assert 'structure.members.read' not in original_caps['capability']['operations'],'the original restricted endpoint must not widen'
            print(json.dumps({'state':'PASS','checks':['original0.3.28 runtime replacement','unchanged original profile','authenticated local-owner adoption','two MCP frontends','old operation offline recovery','old endpoint remains restricted','identity/config/journal continuity'],'original_command_preserved':True,'new_workspace_approval':False,'private_state':'SYNTHETIC_ONLY'}))
        finally:
            if ready:
                try:subprocess.run([str(cli),'runtime','admin',str(ready['admin_endpoint']),'stop'],cwd=root,env=env,capture_output=True,timeout=15)
                except Exception:pass
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=15)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
            # An adopted candidate is detached from its initial CLI. Wait for
            # its original ownership fence before deleting synthetic state.
            fence=root/'runtime/runtime.state'
            if fence.exists():
                import fcntl
                end=time.monotonic()+20
                while True:
                    with fence.open('rb') as stream:
                        try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        except BlockingIOError:
                            assert time.monotonic()<end,'synthetic adopted runtime did not release ownership'
                        else:break
                    time.sleep(.05)

if __name__=='__main__':main()
