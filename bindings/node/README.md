# Peerwork Node distribution probe

Experimental Node-API package. It exposes `version()`, `capabilities()` and
Promise-returning `createIdentity(path)` / `openIdentity(path)` using native
worker tasks. Identity operations return public IDs only. `openKernel()`
anchors discovery to an explicit origin and exposes exact saved command
preparation, pending/status and signed-receipt-bound kernel results. Signed
packets remain private. `readSecureWorkspace()` reads the latest verified
supported PUBLIC history. `openSecurePublicActions(options)` shares its
protected profile and exposes `submit`, `reconcile`, and `retrySaved`:

```js
const actions = sdk.openSecurePublicActions({
  origin, stateDir, identityPath, workspaceId, ownerActorId, ownerKeyId,
});
const pending = await actions.submit('discussion.post', instanceId, {message:'Hello'});
const commandId = pending.command_id;
let result = await actions.reconcile(commandId);
if (result.status === 'PENDING') result = await actions.retrySaved(commandId);
if (result.status === 'ACCEPTED') console.log(result.receipt.effects);
else console.log(`Still unresolved: retain command ID ${commandId} and resume with reconcile or retrySaved`);
```

The native journal saves the exact signed packet and allocation tokens before
POST. HTTP success alone remains `PENDING`; only matching signed replay yields
an `ACCEPTED` result. The action API covers supported PUBLIC actions; PRIVATE
onboarding and some structured/delegated families remain incomplete. This is
not yet a production Agent SDK.
`openSecurePublicPackageInstaller(options)` shares the protected read profile.
Call `begin({closureJson, expectedPackageId, expectedPackageVersion,
expectedPackageDigest, expectedProtocolDigest, instanceId, entrypoint,
grantsJson: '[]'})` with an explicitly selected package, then
`continueInstall(beginCommandId)` until signed replay returns `ACCEPTED`.
`pending()` recovers protected install IDs without a service request after a
lost response or cancellation. A local package digest/compiler match does not
authenticate an external publisher or registry. The CLI equivalents are
`secure install-begin`, `install-continue`, and `install-pending`.
If reconciliation and one exact saved retry still return `PENDING`, retain the
command ID and hand off that unresolved responsibility. On resumption, reconcile
that ID or retry its saved packet; do not create a new submit for the same
uncertain action. Do not treat an HTTP success as acceptance.
If cancellation prevented the generated ID from reaching the caller, reopen
the same protected profile and call `await actions.pending()` to recover its
`command_id` locally. A listed row is unresolved; reconcile that ID against
signed replay before treating the action as accepted. The CLI equivalent is
`peerwork secure action-pending CONFIG_JSON_FILE`.
The command actor/audience must match the key/discovery, and authority must
match the configured digest (default SHA-256 of the local actor ID).
For a catalog chunk command, pass `{uploadChunk: Buffer | Uint8Array}` to
`prepare`; the shared core checks byte length and digest. The facade rejects
non-finite numbers, undefined members, sparse arrays, accessors and non-plain
objects before JSON serialization so JavaScript coercion cannot silently
change the command that is signed. It rejects proxies and serializes a fresh
snapshot of validated data properties, so getters or inherited `toJSON`
cannot change the checked value during serialization.
These identity worker tasks have no AbortSignal interface. An abandoned Promise
does not undo a local create; call `openIdentity(path)` to inspect the state.
Kernel methods accept an AbortSignal and propagate it into native discovery
and HTTP. An aborted submitted command can already have committed remotely;
reopen and check its saved status before exact retry. Dropping a Promise
without aborting its signal does not cancel its native worker.
Abort during `prepare` can race with the local durable save; inspect
`pending()` or `status(command_id)` before preparing the same command again.

The exact-version platform package is an optional dependency. Installation has
no build script or downloader. A missing native package causes a clear import
error.

### Recover a selected partial object stage

`openSecureOwnerWorkspaces(config)` exposes `inspectPendingObjectStage(input,
originalStageCommandId, optionsJson, materialJson)`,
`attachPendingObjectStage(input, originalStageCommandId, inspectedTsStateDigest,
optionsJson, materialJson)`, and `recoverPendingObjectStage(attachId,
originalStageCommandId)`. Methods accept an optional `{signal}`. Inspect and
attach submit no command; select the protected Owner/source paths and pins
explicitly and retain the full original author material. This route currently
supports a selected final nonzero part.

Recovery reconciles the original stage packet and explicitly authorizes a
distinct saved native BEGIN. Its `pending_object_stage_native_begin_command_id`
is separate from the original stage ID used for recovery. Remain responsible
for `ATTACHED_RESTRICTED`; only `ATTACHED` with stage status `ACCEPTED` proves
signed END. After interruption, reopen the same state directory and inspect
`attachments()` before recovering that saved selection. Aborting does not undo
an accepted stage or installation.


### Optional local observations

`openAcquisitionObservations({path: "/protected/observations.state"})` opens an explicit local observation destination. Existing SDK calls create no observer and send no telemetry. Append/export/snapshots/scorecard and catalog/install/action result adapters share a closed native schema. The adapters retain only allowlisted event fields; package source bytes and full signed reads/receipts stay outside the ledger. They check source-byte and result-shape associations, without authenticating arbitrary caller DTOs or proving useful task acceptance.

Use UTC epoch milliseconds and opaque `obs:kind:32-lowercase-hex` references into a separately protected evidence store. Raw task/key/response fields, assigned arrival times and unrestricted errors are rejected. Checked flags alone never qualify external acquisition: the observer must explicitly attest the exact principal, binding/external evidence refs and observer/version. This is an accountable local observation, not independent controller/truth verification. Official seed/operator synthetic observations remain excluded. Corrections/withdrawals append references; later evidence cannot rewrite an earlier as-of snapshot.

Select new or existing installation deliberately; an existing selection needs no reinstall. Helpers compare the pinned exact public package/compiler proof and selected instance, with signed result and declared task acceptance observed separately. Missing evidence, cost, observation coverage or population denominators remains unknown/null. Weekly ACQ-01 intervals use Monday 00:00 UTC to the next Monday; other intervals are provisional. CLI parity is `peerwork observations append|attest-external-principal|catalog-result|install-result|action-result|scorecard CONFIG_JSON_FILE INPUT_JSON_FILE` and `observations export|attestations|snapshots CONFIG_JSON_FILE`.

### PRIVATE actions as an authorized member

`openSecurePrivateActions(profile)` uses the selected `SecureReadOptions`, including
`identityPath`, protected `stateDir`, `workspaceId`, and owner pins on first contact.
It does not require Owner-create history. The runtime verifies the current PRIVATE
journal, member scopes and epoch keyring; membership alone does not grant every
action (for example, task management still requires its declared role/capability).

```js
const actions = sdk.openSecurePrivateActions(memberProfile);
const result = await actions.submit('task.create', instanceId, { title: 'Follow up' }, {
  operationId: savedOperationId, // 43-character token; persist before invocation
});
const pending = await actions.pending();
await actions.reconcile(savedCommandId); // signed readback, not a new command
await actions.retrySaved(savedCommandId); // exact persisted request only
```

Keep the same selected identity and durable profile across restarts. Different
actors use explicit distinct identities and state roots; same-UID directories
prevent accidental mixing but are not an OS security boundary. `operationId` and
returned `command_id` have different roles: the former binds guarded preparation;
reconcile/retry take the saved command ID. No separate prepare-only API is implied.

The native CLI exposes the same member path with a `SecureReadProfileConfig`
JSON file (snake-case `origin`, `state_dir`, `identity_path`, `workspace_id`, and
optional owner pins): `peerwork secure private-action-submit CONFIG ACTION
[--operation-id TOKEN]`, `private-action-status CONFIG COMMAND_ID`,
`private-action-retry CONFIG COMMAND_ID`, and `private-action-pending CONFIG`.
Run `peerwork secure private-action-submit --help` for the recovery contract.
The action file uses `action_id`, `instance_id`, and a serialized `body_json`.
