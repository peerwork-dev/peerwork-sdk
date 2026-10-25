# Owner self-service legacy workspace migration

SDK/CLI support: **0.2.2**. Require service discovery feature
`owner-self-service-archive-migration-v1` before calling this operation.
Release availability is recorded in [0.2.2 release notes](../RELEASE_NOTES_0.2.2.md).

An archived workspace is unavailable for ordinary reads and writes until its
Owner authorizes migration. The Owner uses one native SDK call; the Backend
exports the selected encrypted source, validates the signed conversion in
isolation, imports it in resumable transactions and activates the workspace.
A platform operator does not run an import command for each workspace.

## One call

Use the existing Owner identity and its selected private profile directory.
Stop other Owner operations on that directory during local source capture.
Do not create a replacement identity or send signing seeds, epoch keys or body
keys to the service. Keep the directory 0700 and its files 0600.

```js
const sdk = require('@peerwork/agent-sdk');
const client = await sdk.openKernel({
  origin: 'https://api.peerwork.dev',
  identityPath: '/private/owner/identity.state',
  journalPath: '/private/owner/operations.sqlite',
  // authority: existingAuthorityPin, // preserve an existing non-default pin
});
const result = await client.migrateArchive({
  workspace_id: 'WORKSPACE_ID',
  idempotency_key: 'restore-legacy-space-1',
  state_dir: '/private/owner',
  read_only_snapshot: true,
  name: 'Historical workspace',
});
if (result.state === 'PENDING') {
  // The Backend continues an admitted migration after this process exits.
  // Persist the original command_id; never replace it to resolve uncertainty.
  console.log(await client.resumeStructureIntent(result.command_id));
}
```

```python
import peerwork
client = peerwork.KernelClient(
    'https://api.peerwork.dev', '/private/owner/operations.sqlite',
    '/private/owner/identity.state',
    # authority=existing_authority_pin,
)
result = client.migrate_archive({
    'workspace_id': 'WORKSPACE_ID',
    'idempotency_key': 'restore-legacy-space-1',
    'state_dir': '/private/owner',
    'read_only_snapshot': True,
})
if result['state'] == 'PENDING':
    result = client.resume_structure_intent(result['command_id'])
```

For CLI, save the same snake_case selection as `migration.json`:

```sh
peerwork kernel migrate-archive https://api.peerwork.dev \
  /private/owner/operations.sqlite /private/owner/identity.state migration.json
peerwork kernel resume-intent https://api.peerwork.dev \
  /private/owner/operations.sqlite /private/owner/identity.state ORIGINAL_COMMAND_ID
```

An explicit existing authority pin can be passed as `--authority=PIN`.
The native Node, Python and CLI interfaces use the same durable implementation.
Python also offers `migrate_archive_async`.

## Existing prepared checkpoint

If the Owner already has a complete signed checkpoint, select it directly:

```json
{
  "workspace_id": "WORKSPACE_ID",
  "idempotency_key": "restore-prepared-1",
  "checkpoint_path": "/private/owner/checkpoint.jsonl"
}
```

The SDK verifies the file's Owner signatures, workspace/authority binding,
packet chain, final digest and the service's current frozen snapshot before
upload. An artifact from an earlier rehearsal returns
`MIGRATION_SNAPSHOT_CHANGED`; it is never silently rebound. Use a new explicit
source selection to prepare from the current frozen source. A custom
`plan_path` can select a reviewed mapping; its source binding is checked too.

## What the SDK and Backend each do

1. The SDK reads signed current source metadata and submits an Owner-signed,
   dedicated-recipient source request. Only that workspace's encrypted archive
   is downloaded. The SDK verifies its pinned service evidence and captures a
   verified encrypted local capsule once.
2. Locally, the SDK derives the structure/body mapping, preserves provenance,
   encrypts narrative bodies in the new format and signs the complete bounded
   checkpoint. Existing identity, history and keys stay on the Owner host.
3. The SDK uploads one bounded artifact stream. The service commits 32 KiB
   offsets; interruptions resume from a signed observed offset. The default
   artifact limit is 64 MiB. A partial upload is never queued for import.
4. Backend validation uses isolated staging. Invalid signatures, references,
   mappings or hashes leave the actual workspace archived. A validated artifact
   is imported in bounded transactions using durable page offsets. Activation
   is atomic; ordinary operations on other spaces continue.
5. The SDK waits for a fresh signed `COMPLETE` result. Timeout, cancellation or
   connection loss returns `PENDING` with the original operation ID. Resume
   observes that operation; it does not create a second conversion. Completed
   jobs can be observed even after the local checkpoint is removed.

The explicit migration call waits up to 180 seconds, including initial local
source verification. This is a one-time history operation: large archives can
return `PENDING` and need continuation. It is not a promise that arbitrary
history sizes finish in a fixed duration. Ordinary actions do not replay history
and retain their existing deadlines. Local verified capsules and signed files
are reused after interruption. A backend restart resumes its accepted jobs.

## Result, privacy and limitations

The supported default is an explicit `READ_ONLY_SNAPSHOT`: retained record
IDs/revisions, current heads, instances, relations and historical attribution
are preserved; narrative bodies remain E2EE. Business structure becomes readable
under workspace access controls. The Owner signs the new representation; this
is not a new signature by each historical author. Original protocols and
signed source evidence remain preserved.

The target has an inert snapshot protocol. Old workflow dependencies, reminders
and actions are not automatically restored. Old memberships, grants and PUBLIC
publication are not re-enabled. The workspace starts PRIVATE with its Owner;
new access, protocols and publication require their own explicit actions.

Missing local decryption keys cannot be repaired by server authorization.
Unclassified entity withdrawals are refused rather than recreating removed
heads. Structured refusals identify phase, original code, retryability and
recovery. Local mapping failures reuse the verified capsule after correction;
validation failures require an explicitly corrected new operation. Storage or
live import interruptions retain their accepted artifact and original job.

Deployment initializes source metadata and the isolated migration role once.
The internal `convert-owner-checkpoint --live-archived` tool remains an operator
recovery tool; it is not a prerequisite for the SDK workflow above.
