# PRIVATE protocol installation: transport and recovery

Available in the [published **0.1.11 experimental native release**](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.1.11-experimental.39718835871).
Source: `98594c558454a489b25e4a74f0c333aecc44eb49`. Version 0.1.10 does not provide the methods below.
The matching policy-restoring service update is deployed at `api.peerwork.dev`.
Other services still need their own matching qualified update. Check the target service at `GET /api/workspace/v1/install-capabilities`:
it must report `recovery_profile: owner-single-invalid-inline-install-v1`,
`policy_restore: EXACT_PREDECESSOR_STRUCTURE` and minimum native SDK **0.1.11**.
The SDK performs this check and returns `INSTALL_RECOVERY_SERVICE_UNSUPPORTED`
before writing when the profile is absent. The public profile is advisory;
complete signed journal verification still decides authority and acceptance.
Do not apply recovery to a production workspace until availability is confirmed.
Upgrade clients that verify this workspace's complete history before applying
policy-restoring recovery. Their existing protected identities and state stay in
place; old verifiers may refuse the repaired history rather than skip its checks.

## Transport is an SDK responsibility

An Agent selects a protocol, instance, grants and disclosure. It should not
calculate wire sizes, split a protocol object or prepare encrypted transport
packets. The SDK measures canonical UTF-8 bytes of the complete wire object,
including its envelope. The limit is **98,304 bytes per object**.

Small DIRECT installations keep their existing BEGIN/PAGE/END path. For a large
new protocol object, an existing PRIVATE wire-v3 STRUCTURED workspace and the
service's `signed-protocol-object-source-v1` capability permit automatic object
staging. The compiled value is split into bounded parts with deterministic
source/part hashes. Every encrypted part is signed once and saved before POST.
Only its exact verified signed ancestry can authorize the next part and BEGIN.
This is distinct from staging a package's author material: a small package can
compile to a large protocol object. Automatic selection currently applies to
`beginDirect`. Explicit package-stage installation keeps its chosen path and
returns `INSTALL_OBJECT_TOO_LARGE` before BEGIN if its inline object is oversized;
it does not silently replace the selected source or provenance.

A staging prerequisite failure is reported before any installation POST. The
SDK does not silently upgrade a workspace's wire format, change disclosure,
create a new identity, replace keys or replan a conflicting source.

```js
const installer = owner.privatePackageInstaller(workspaceId);
// Persist this 43-character ID before starting. It also identifies the future
// BEGIN while the SDK is still staging object parts.
let progress = await installer.beginDirect(selection, {commandId: installId});
while (progress.status !== 'ACCEPTED') {
  progress = await installer.continueInstall(installId);
}
```

`step_action_id` identifies `secure.protocol-object.stage`,
`secure.structure.begin`, `secure.structure.page` or `secure.structure.end`.
A step response is not proof that installation is usable; only a verified END
and ACTIVE read establish completion. After interruption, use `installs()` to
discover the saved ID and continue it. OBJECT_STAGING rows expose their phase
and saved step count without returning material or private record bodies.
Uncertain outcomes reuse the same saved packet. Source conflicts are retained
for diagnosis rather than silently replaced with new commands.

## Read-only diagnostics

Node: `await installer.diagnose(originalBeginId)`.
Python: `installer.diagnose(original_begin_id)` or `await installer.diagnose_async(...)`.
CLI:

```sh
peerwork secure owner-private-install-diagnose OWNER_CONFIG WORKSPACE BEGIN_ID
```

The report has schema `peerwork.install-diagnostic.v1`, `submitted: false`, and
an explicit `verified` result. Verification failures retain a fixed stage,
class, check and optional sequence. Cached profile replay, fresh installation
replay and checkpoint-floor checks remain distinguishable. Diagnostics do not
return decrypted records, package material or keys, sign a command, POST a
transaction or replace the protected ACTIVE generation. Candidate read caches
may be updated locally.

A fixture-export error such as unsupported relation history is a separate
projection limitation. It must not be presented as a journal signature failure.

## An invalid committed BEGIN is immutable

0.1.10 could author an oversized inline protocol object, save and submit BEGIN,
then reject that same object during continuation. The server cannot inspect an
encrypted business body to catch this client-side mistake. Restoring local files
cannot make the signed body conform to the object limit. Do not delete the intent,
re-sign the same command ID, clear the ACTIVE cache, skip verification or replace
an identity to work around it.

The candidate supports an explicit narrow recovery for **one invalid inline
BEGIN immediately after the verified ACTIVE predecessor**. It first verifies
complete signatures, key material, service guard-time attestations and exact
checkpoint ancestry, then reproduces that object's size failure. Signature,
key, provenance and arbitrary unsupported-history failures are not eligible.
Imported historical installs and wider suffixes are outside this recovery path.

```js
const plan = await installer.recoveryPlan(originalBeginId); // no POST
// Review the exact base/through range and target structure hash. Persist the
// approved review hash and a new stable recovery operation ID before writing.
let recovery = await installer.recoverInvalid(originalBeginId, {
  expectedReviewHash: plan.review_hash,
  operationId: recoveryId,
});
while (recovery.status !== 'ACCEPTED') {
  recovery = await installer.recoverInvalid(originalBeginId, {
    expectedReviewHash: plan.review_hash,
    operationId: recoveryId,
  });
}
```

The Owner-signed disposition retains the original BEGIN and all signatures in
history, excludes only the reviewed invalid operation from active content, and
restores the exact predecessor's structure policy. Current membership,
certificates, scopes, epoch, guard-time policy and format ceiling are preserved.
A policy update cannot widen the excluded range, select another structure or
carry an unrelated authority change. Snapshot PAGE/END packets are saved and
reconciled with the same exact-packet rules before ACTIVE is restored.

The original install remains discoverable with `recovered_by`; this local field
alone is not remote acceptance evidence. Continuing its original ID returns
`INSTALL_RECOVERED_NEW_BEGIN_REQUIRED`. To install the selected protocol, start
`beginDirect` with a **new** install ID. Automatic object staging then selects the
safe transport. Neither operation migrates an identity or imports new keys.

Python exposes `recovery_plan` / `recovery_plan_async` and
`recover_invalid` / `recover_invalid_async`, with `expected_review_hash` and
`operation_id` keyword arguments. CLI equivalents are:

```sh
peerwork secure owner-private-install-recovery-plan OWNER_CONFIG WORKSPACE BEGIN_ID
peerwork secure owner-private-install-recover OWNER_CONFIG WORKSPACE REVIEWED_REQUEST_JSON
```

The reviewed request contains exactly `begin_command_id`,
`expected_review_hash` and `operation_id`. Reuse those exact values after PENDING,
a process restart or a lost response. A changed checkpoint or review hash causes
a refusal rather than a broader recovery.
