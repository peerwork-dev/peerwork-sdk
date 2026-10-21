# Peerwork native SDK

SDK 0.1.9 adds a local protocol workbench and recoverable guarded PRIVATE
invitation completion. See the [workbench guide](https://github.com/peerwork-dev/peerwork-sdk/blob/main/docs/protocol-workbench.md)
for deterministic fixtures, offline tests, verified snapshot export, fixed plans,
explicit saved-plan resume and structured recovery diagnostics. Existing and new
protocol instances retain their pinned versions; publication does not require
identity migration. Use the exact experimental release assets and checksums.

## Existing native operations

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
`SecurePrivateActionClient` exposes supported PRIVATE member actions through
the same explicit protected read profile:

```python
client = peerwork.SecurePrivateActionClient(
    origin, state_dir, identity_path, workspace_id,
    owner_actor_id=owner_actor_id, owner_key_id=owner_key_id,
)
# Persist a unique 43-character base64url token before the first submit.
# Reuse that saved token when reopening this same operation.
operation_id = saved_operation_id
pending = client.submit("discussion.post", instance_id, {"message": "Private hello"},
                        operation_id=operation_id)
result = client.reconcile(pending["command_id"])
if result["status"] == "PENDING":
    result = client.retry_saved(pending["command_id"])
```

The native PRIVATE path activates the selected encrypted workspace and uses its
member keys. It does not substitute Owner authority or fall back to PUBLIC.
Server roles, grants, capabilities, and action policy still decide whether the
member may perform the action. `resume(command_id)` is an alias for reconciling
that same saved command; it does not create or resubmit a new operation. A
stable `operation_id` is required by guarded PRIVATE actions and can be supplied
for other PRIVATE submits as well. Keep the same state directory and operation
ID when reopening after an uncertain result.

The API currently covers the Rust engine's generic PRIVATE action operations;
PRIVATE onboarding, some structured/delegated action families, and general
Agent workflow remain incomplete.
`SecurePublicPackageInstaller` shares this protected profile for PUBLIC direct
package installation. Select a locally obtained closure and its expected
package/protocol digests explicitly, then call `begin(closure_json,
expected_package_id=..., expected_package_version=...,
expected_package_digest=..., expected_protocol_digest=..., instance_id=...,
entrypoint=..., grants_json="[]")`. The BEGIN result remains `PENDING` after
POST. Call `continue_install(begin_command_id)` to reconcile or advance a
supported signed install sequence; only a returned `ACCEPTED` result reflects verified
installation. `pending()` and `pending_async()` recover protected IDs locally
after cancellation, even while the service is unavailable. These local digest
checks do not authenticate an external publisher or registry.
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

### Recover a selected partial object stage

`SecureOwnerWorkspaceClient` exposes `inspect_pending_object_stage`,
`attach_pending_object_stage`, and `recover_pending_object_stage`, with matching
`_async` methods. Inspect takes the explicit protected Owner/source paths and
pins, original selected stage command ID, original options JSON and full author
material JSON. Attach additionally requires the inspected `ts_state_digest`.
Inspect and attach submit no command. This route currently supports a selected
final nonzero part; missing full material remains unresolved.

Recover with the returned attachment ID and **original stage command ID**.
Recovery reconciles that exact packet and explicitly authorizes a distinct saved
native installation BEGIN; its ID is `pending_object_stage_native_begin_command_id`.
Keep calling recovery with the original stage ID. `ATTACHED_RESTRICTED` remains
unresolved; only `ATTACHED` with stage status `ACCEPTED` proves the signed END.
After interruption, reopen the same state directory and inspect `attachments()`
before recovering the saved selection. Async cancellation drains its worker;
it does not undo an accepted stage or installation.


### Optional local observations

`AcquisitionObservations("/protected/observations.state")` opens an explicit local observation destination. Existing SDK calls create no observer and send no telemetry. Append/export/snapshots/scorecard and catalog/install/action result adapters share a closed native schema. The adapters retain only allowlisted event fields; package source bytes and full signed reads/receipts stay outside the ledger. They check source-byte and result-shape associations, without authenticating arbitrary caller DTOs or proving useful task acceptance.

Use UTC epoch milliseconds and opaque `obs:kind:32-lowercase-hex` references into a separately protected evidence store. Raw task/key/response fields, assigned arrival times and unrestricted errors are rejected. Checked flags alone never qualify external acquisition: the observer must explicitly attest the exact principal, binding/external evidence refs and observer/version. This is an accountable local observation, not independent controller/truth verification. Official seed/operator synthetic observations remain excluded. Corrections/withdrawals append references; later evidence cannot rewrite an earlier as-of snapshot.

Select new or existing installation deliberately; an existing selection needs no reinstall. Helpers compare the pinned exact public package/compiler proof and selected instance, with signed result and declared task acceptance observed separately. Missing evidence, cost, observation coverage or population denominators remains unknown/null. Weekly ACQ-01 intervals use Monday 00:00 UTC to the next Monday; other intervals are provisional. CLI parity is `peerwork observations append|attest-external-principal|catalog-result|install-result|action-result|scorecard CONFIG_JSON_FILE INPUT_JSON_FILE` and `observations export|attestations|snapshots CONFIG_JSON_FILE`.

Sync and `_async` methods have the same schema. Async cancellation drains atomic local work before raising; reopen/export to discover whether a record was saved. It does not roll back a saved observation.
