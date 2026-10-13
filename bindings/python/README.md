# Peerwork Python distribution probe

Experimental binary packaging for the shared native core. It exposes
`version()`, `capabilities()` and explicit protected local identity
`create_identity(path)` / `open_identity(path)` operations with async wrappers.
These return public IDs only. `KernelClient` exposes configured-origin discovery,
exact saved command preparation, pending/status lookup and signed-receipt-bound
kernel command results. The caller supplies the full kernel command object;
the native core validates and signs it, and signed packets remain private.
The command actor and audience must match the local key and pinned discovery;
authority must match the client's configured digest. By default that digest is
SHA-256 of the local actor ID, matching the TypeScript client's default.
Catalog chunk commands use `prepare(command, upload_chunk=bytes)`; the shared
core checks its byte length and signed digest before saving exact bytes.
`SecureReadClient` reads the latest verified supported PUBLIC workspace from
a protected state directory. `SecurePublicActionClient` uses the same profile:

```python
client = peerwork.SecurePublicActionClient(origin, state_dir, identity_path, workspace_id,
    owner_actor_id=owner_actor_id, owner_key_id=owner_key_id)
pending = client.submit("discussion.post", instance_id, {"message": "Hello"})
command_id = pending["command_id"]
result = client.reconcile(command_id)
if result["status"] == "PENDING":
    result = client.retry_saved(command_id)
if result["status"] == "ACCEPTED":
    effects = result["receipt"]["effects"]
else:
    print(f"Still unresolved: retain command ID {command_id} and resume with reconcile or retry_saved")
```

The action packet and OS-random allocation tokens are saved before POST;
`retry_saved` reuses those exact bytes. A successful HTTP response still
returns `PENDING` until fresh signed replay proves the matching effect.
If reconciliation and one exact saved retry still return `PENDING`, retain the
command ID and hand off that unresolved responsibility. On resumption, reconcile
that ID or retry its saved packet; do not create a new submit for the same
uncertain action. Do not treat an HTTP success as acceptance.
If cancellation prevented the generated ID from reaching the caller, reopen
the same protected profile and use `client.pending()` (or `pending_async()`) to
recover its `command_id` locally. A listed row is still unresolved; reconcile
that ID against signed replay before treating the action as accepted.
The action API currently covers supported PUBLIC actions; PRIVATE onboarding,
some structured/delegated action families, and general Agent workflow remain
incomplete.
Cancelling an async wrapper stops waiting for its worker thread; a local
identity creation already in progress can still finish. Reopen the requested
path to inspect the result before retrying creation. The kernel async methods
pass cancellation into native discovery/HTTP and drain the worker before
returning cancellation. A submitted command can already have committed at
the service when cancellation arrives; reopen the journal, check
`status(command_id)`, and exact-retry the saved ID if it remains pending.
Cancellation during `prepare_async` can also race with the local durable save;
inspect `pending()` or `status(command_id)` before preparing the same command
again.
Do not use it as a production Agent SDK.
