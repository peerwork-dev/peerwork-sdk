import asyncio,json,secrets,sys
import peerwork
v=json.load(open(sys.argv[1]));owner=peerwork.SecureOwnerWorkspaceClient(**v['config']);client=owner.member_scopes(v['workspace_id'])
before=client.inspect(v['actor_id']);assert before['scopes']==[]
changed=client.set(v['actor_id'],expected_policy_hash=before['policy_hash'],scopes=v['scopes'],operation_id=secrets.token_urlsafe(32));assert changed['status']=='ACCEPTED'
assert client.recover(changed['operation_id'])==changed
async def main():
 current=await client.inspect_async(v['actor_id']);assert current['scopes']==v['scopes']
 result=await client.set_async(v['actor_id'],expected_policy_hash=current['policy_hash'],scopes=[],operation_id=secrets.token_urlsafe(32));assert result['status']=='ACCEPTED'
 assert await client.recover_async(result['operation_id'])==result
 assert await client.retry_saved_async(result['operation_id'])==result
 assert any(r['operation_id']==result['operation_id'] for r in await client.history_async())
asyncio.run(main());assert len(client.history())>=4
print(json.dumps({'status':'PASS'}))
