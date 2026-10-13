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
