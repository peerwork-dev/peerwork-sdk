// Owner config and operation IDs are nonsecret; the selected profile holds keys.
import {readFile} from 'node:fs/promises';
import {openSecureOwnerWorkspaces} from '@peerwork/agent-sdk';
const [configPath,workspaceId,actorId,operationId,scopesPath]=process.argv.slice(2);
if(!configPath||!workspaceId||!actorId||!operationId||!scopesPath) {
  throw new Error('Usage: node update.mjs OWNER_CONFIG WORKSPACE ACTOR SAVED_OPERATION_ID SCOPES_JSON');
}
const config=JSON.parse(await readFile(configPath,'utf8'));
const owner=openSecureOwnerWorkspaces(config);
const client=owner.memberScopes(workspaceId);
const current=await client.inspect(actorId);
console.log(JSON.stringify(await client.set(actorId,{
  expectedPolicyHash:current.policy_hash,
  scopes:JSON.parse(await readFile(scopesPath,'utf8')),
  operationId,
})));
// On interruption, open the same profile and client.recover(operationId).
// retrySaved(operationId) explicitly permits resending the same saved packet.
