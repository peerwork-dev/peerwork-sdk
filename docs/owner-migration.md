# Migrating an existing TypeScript Owner

Use the existing Owner signing key, service origin and workspace pins. This is
client-state migration, not workspace ownership transfer. Stop the old client
before inspection and keep its protected state, PKCS#8 PEM and SQLite intent
database together and unchanged throughout attachment.

The guard-time cache compatibility below is implemented in SDK 0.1.5 source.
Use the exact published experimental release when available; source changes
and local tests alone do not establish downloadable binary availability.

The current TypeScript SQLite v2 journal is accepted when its operation-intent
table is empty. The selected exported SQLite file must meet the same private
file protection requirements as the PEM and state JSON. Nonempty `client_operations` remains `SOURCE_UNRESOLVED`; the
importer does not discard these saved application intents. SQLite v1 remains
supported with its existing snapshot pins.

## Completed guard-time actions

The importer accepts absent or empty `guard_time_action_intents` and
`guard_time_post_responses` maps. For nonempty action maps it accepts only
`CONFIRMED` entries for the selected workspace. It verifies each original
input hash, signed command, policy, decrypted business input and refs, service
time attestation, source and result against complete authenticated history.
It does not submit another copy of a completed action.

Python uses the existing explicit attachment method:

```python
owner.attach(
    workspace_id=workspace_id,
    protected_ts_state_path=selected_state_path,
    protected_ts_intent_db_path=selected_intent_db_path,
    protected_owner_pkcs8_path=selected_owner_pem_path,
    expected_owner_actor_id=owner_actor_id,
    expected_owner_key_id=owner_key_id,
)
```

Node uses `owner.attach(input)` with `workspaceId`, `protectedTsStatePath`,
`protectedTsIntentDbPath`, `protectedOwnerPkcs8Path`, `expectedOwnerActorId` and
`expectedOwnerKeyId`. CLI uses `peerwork secure owner-attach OWNER_CONFIG_JSON INPUT_JSON`.
The input object contains the six named fields above; the Owner config selects
the original service `origin` and protected native `state_dir`. Use
`owner.attachments()` / `secure owner-attachments` to recover the original
attachment ID and the corresponding resume method after interruption.

Once attachment reaches `ATTACHED`, reopen the same native Owner profile and
verify `owner.read(workspace_id)` before writing. The native profile supports
verified reads after the old source directory is unavailable. Historical local
TypeScript operation IDs are not converted into new native operation IDs.
Completed effects remain in verified signed history.

## Pending and invalid state

`SOURCE_GUARD_TIME_PENDING` means the source retains a `PREPARING`, `PREPARED`
or `ACCEPTED` timed action, or an unconfirmed generic guard-time POST response.
No completed attachment is established from that state. Preserve the original
Owner and the exact saved operation. Reopen the original TypeScript client;
for a timed action use `resumeGuardTimeAction(workspaceId, operationId)`. For a
generic saved POST, use that operation's original recovery path (`retryPending`
where supported). Verify signed completion, stop the old client, and retry
attachment. Do not delete maps, replace the identity, resign an uncertain
packet, or run both clients concurrently to obtain a migration pass.

`SOURCE_GUARD_TIME_INVALID` means malformed or mismatching cached evidence,
or a timed operation for a different workspace. Keep the original source and
inspect the selected pairing; this is not authorization to discard other
workspace work. Nonempty multi-workspace timed caches are not currently
imported through a one-workspace attachment.

`SOURCE_UNRESOLVED` remains the refusal for other unsupported historical
operation families or unresolved work. It does not by itself prove that the
Owner key is invalid or that a remote action is pending. Provide the installed
version, exact method and redacted error when reporting it; do not publish
protected source files or signing keys.

## Regression boundary

The affected acceptance uses a genuine current TypeScript Owner with enabled
trusted time, a completed action and a saved-before-POST action. It compares
the published 0.1.4 executable with the corrected candidate on the same source,
checks refusal without extra commits, recovers the original operation once,
then migrates, removes the source directory, reopens and verifies native
read/write/retry behavior. This is scripted engineering acceptance; natural
Agent workflow compliance is a separate result.
