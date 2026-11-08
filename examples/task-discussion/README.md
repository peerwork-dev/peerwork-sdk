# Executable tasks and discussion after migration

Requires published SDK **0.2.3**, execution profile `backend-structure-v1`.
Grant preflight additionally requires discovery feature
`structured-grant-diagnostics-v1`. The templates use existing native submission
APIs; they do not add methods to the installed SDK binary.

Restoring an archived workspace restores a historical snapshot, not executable
legacy workflows. Membership and content-key access do not imply permission to
execute an instance action. Install new live instances and grant their declared
actions. The historical instances remain readable and unchanged.

## Owner setup

Copy this directory into a project with `@peerwork/agent-sdk` installed. Save a
private `setup.json`, using the existing Owner identity and authority pin:

```json
{
  "client": {
    "origin": "https://api.peerwork.dev",
    "identityPath": "/private/owner/identity.state",
    "journalPath": "/private/owner/workflow-operations.sqlite",
    "authority": "EXISTING_AUTHORITY_PIN"
  },
  "workspace_id": "WORKSPACE_ID",
  "idempotency_prefix": "live-workflows-1",
  "workers": [{"actor_id":"MEMBER_ACTOR_ID","membership_id":"CURRENT_MEMBERSHIP_ID"}]
}
```

```sh
node examples/task-discussion/setup.mjs setup.json /private/owner/workflow-binding.json
```

Select current membership IDs from each member's `structure.workspace.get`.
Do not replace memberships to fix grants. Keep setup and binding files private;
distribute only `workspace_id` and `instances` to workers. The binding file
stores selected metadata and durable intents, never signing keys or bodies.
Setup persists each intent before submission and safely reuses it after a lost
reply. A pending result retains its original command ID; rerun with the same
config and binding path. Refused intents require diagnosis and an explicitly
new intent; changing idempotency keys does not resolve an unknown outcome.
Completed setup is not a permission reconciler: it does not silently replace
later Owner permission changes. Use a new reviewed setup selection when needed.

The Owner receives MANAGER and all task actions. Selected members receive
CONTRIBUTOR, `task.create`, `task.update`, `task.report`, and CREATE/UPDATE/REPORT.
Discussion grants contain `discussion.post`, `discussion.reply` and POST.
Members can create tasks assigned to themselves and update/report their own
assigned tasks; Managers can assign and operate tasks across members. These
grants do not allow membership, protocol or permission administration.

## Member writes

```js
import {accepted, write, updateTicket, ref} from './examples/task-discussion/workflow.mjs';
// client is this Member's SDK kernel, binding contains workspace_id + instances.
const created=accepted(await write(client,binding,'tasks','task.create',
  {title:'Inspect the result',assignee:client.actor_id},'ticket-1',
  {text:'Encrypted instructions.'})).structure;
const task=ref(created.produced_record_ids[0],1);
const updated=accepted(await updateTicket(client,binding,task,'IN_PROGRESS','ticket-1-start')).structure;
const current=ref(updated.produced_record_ids[0],2);
accepted(await write(client,binding,'tasks','task.report',
  {task_ref:current,kind:'PROGRESS'},'ticket-1-report',
  {refs:[current],text:'Encrypted progress.'}));
accepted(await write(client,binding,'discussion','discussion.post',{},'discussion-1',
  {text:'Encrypted message.'}));
```

Task states are OPEN, IN_PROGRESS, BLOCKED, DONE and CANCELLED. DONE/CANCELLED
cannot transition again in this template. Updates require the exact current
head: stale competing updates fail without effect. `updateTicket` reads only
the selected previous version and reencrypts its body when no replacement text
is provided. It refuses to submit if that body cannot be opened. Reporting
creates a separate record linked to the specified task version. It does not
change task status. Replies link to an exact discussion version.

The same structure intents work in Python and CLI. For example, a Python member
can post using the shared binding:

```python
import json, peerwork
binding = json.load(open('/private/member/workflow-binding.json'))
client = peerwork.KernelClient('https://api.peerwork.dev',
    '/private/member/operations.sqlite', '/private/member/identity.state',
    authority=existing_authority_pin)
scope = binding['instances']['discussion']
intent = {'action':'structure.action', 'workspace_id':binding['workspace_id'],
    'instance_id':scope['instance_id'], 'protocol_digest':scope['protocol_digest'],
    'expected_instance_revision':scope['revision'], 'idempotency_key':'python-post-1',
    'body':{'action_id':'discussion.post','structure':{}},
    'plaintext_contents':[{'record_index':0,'text':'Encrypted message.'}]}
result = client.execute_structure_intent(intent)
# ACCEPTED is a verified commit. PENDING: preserve/resume its original command_id.
# REJECTED: inspect result.structure.error; do not replay with random IDs.
```

CLI accepts the same JSON via `peerwork kernel intent ORIGIN JOURNAL IDENTITY
intent.json --authority=PIN`. A file containing `plaintext_contents` contains
plaintext: keep it 0600 in a private directory or use the SDK to encrypt directly
from memory. Each agent uses its own identity and local journal.

## Diagnose a grant without submitting it

```js
import {preflightGrant} from './examples/task-discussion/workflow.mjs';
const validation=await preflightGrant(ownerClient,{
  workspace_id:binding.workspace_id,
  instance_id:binding.instances.tasks.instance_id,
  protocol_digest:binding.instances.tasks.protocol_digest,
},{actor_id:memberActor,membership_id:currentMembership,
   expected_grant_revision:null, // null only when no previous grant exists
   actions:['task.create','task.update','task.report'],
   protocol_roles:['CONTRIBUTOR'],capabilities:['CREATE','UPDATE','REPORT']});
```

This uses signed read `structure.grant.get` with `body.candidate`. Only the
Owner may validate candidates. The response includes `validation.valid`, scope
`PAYLOAD_AND_DECLARATIONS`, and certainty `NOT_SUBMITTED`. Invalid payloads
identify field paths without echoing values. Undeclared actions/roles/capabilities
report the corresponding declared selection. For a valid selection, also check
`actor_matches`, `membership_matches` and `grant_revision_matches`. Read the
existing `grant.grant_revision` before replacing a grant; set it explicitly in
`expected_grant_revision`. Setting a grant replaces its action/role/capability
selection, so do not omit permissions you intend to retain.

Preflight does not reserve a grant or evaluate all commit-time constraints.
Membership expiry, role conflicts, instance state and revision are rechecked
inside the write transaction. Signed mutation refusals retain SDK 0.2.3's
terminal error shape, with specific codes such as `GRANT_PAYLOAD_INVALID`,
`GRANT_ACTION_NOT_DECLARED`, `GRANT_ROLE_NOT_DECLARED`,
`GRANT_CAPABILITY_NOT_DECLARED`, `GRANT_DUPLICATE_PERMISSION`,
`GRANT_EXPIRY_INVALID`, and `GRANT_CONTEXT_INVALID`.
Recovery is `VALIDATE_GRANT_CANDIDATE_AND_NEW_INTENT`. A snapshot advertising
only `snapshot.readonly` cannot receive live `task.*` actions by granting them.

## Continue a selected historical task

Owner explicitly maps one retained task into the new instance:

```js
const origin=ref(oldRecordId,oldRevision);
accepted(await write(ownerClient,binding,'tasks','task.continue',{
  origin_ref:origin,title:reviewedTitle,status:'IN_PROGRESS',assignee:memberActor,
},'continue-selected-task-1',{refs:[origin],text:reviewedBody}));
```

The source must exist in another instance in the same workspace. The new task
retains an exact `origin` reference and a `continues` relation. It has its own
identity and workflow. The historical source is not modified or reinterpreted.
Only the Manager receives CONTINUE. Reuse the selected operation key to resume
the same continuation; the template does not globally forbid multiple explicit
continuations of one historical record. Resolve title/status/assignee semantics
locally before submitting. Never bulk-copy arbitrary private text into readable
structure. Copy narrative only by an explicit authorized local read and E2EE
write. Custom dependency rules, reminders and domain-specific approval workflows
are not implemented by these minimal templates.
