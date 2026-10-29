# Attach role instructions to an existing instance

SDK 0.2.13 introduces an Owner-authorized **first** bundle attachment through
`ProtocolClient.bind` (Python), `protocols(kernel).bind` (Node), and the native
CLI's existing `kernel intent` command. The service must advertise
`owner-protocol-bundle-binding-v1`; check actual release assets and discovery.
This is not a protocol upgrade or task conversion.

## Diagnose the missing selection

An instance adopted from a bare manifest has an execution digest but no bundle
binding. Installing a newer SDK does not create one. Resolving such an instance
returns a signed `REJECTED_NO_EFFECT` result with
`PROTOCOL_BUNDLE_NOT_BOUND`, HTTP 404, `retryable: false`, and
`recovery: OWNER_BIND_EXACT_PROTOCOL_BUNDLE`. An absent registered package instead
returns `PROTOCOL_BUNDLE_NOT_FOUND`; an unknown role returns
`PROTOCOL_ROLE_NOT_FOUND`. Preserve the actual native outcome and signed code.
A missing binding is not transport uncertainty or evidence of a failed write.

`structure.delivery.routes.read` can return an empty list without a bundle.
An executable delivery route requires a bound package and a currently granted
role. Retrying a failed claim cannot supply the missing package.

## Owner preparation

1. Select the existing workspace, instance and execution digest explicitly.
2. Read the current manifest through the signed `structure.instance.resolve`
   action. Keep its exact normalized rules, initial state, schemas, role names,
   actions and display version. Work from the verified read; do not reconstruct
   rules from task records or infer them from action names.
3. Author a `peerwork.protocol-bundle.v1` with that exact manifest and a resource
   and tool declaration for every declared role. `CONTRIBUTOR`, `RESEARCHER` and
   `WORKER` are different selections; use the instance's declared roles. The
   [bundle contract](protocol-role-bundles.md) describes the complete format.
   Role prose describes existing responsibilities; tool declarations select
   existing action IDs. Current grants continue to filter executable tools.
4. Inspect the package locally and compare its execution digest with the target.
   Package metadata uses its own semantic version; it does not rewrite the
   existing manifest's display version. An unrelated research example package
   cannot attach to a task instance with a different execution digest.

No signing/body keys or private record plaintext need to leave the Owner's
existing environment. Other workspace members cannot perform the attachment.

## One durable attachment

```javascript
const protocols = sdk.protocols(kernel); // existing explicitly selected Owner
const checked = sdk.inspectProtocolBundle(bundle);
if (checked.protocol_digest !== expectedProtocolDigest) {
  throw new Error('The candidate changes existing execution rules');
}
const outcome = await protocols.bind({
  workspace_id: workspaceId,
  instance_id: instanceId,
  protocol_digest: expectedProtocolDigest,
  bundle,
  idempotency_key: stableAttachmentOperationId,
});
// Retain the same input/key for a pending outcome.
// protocols.resume(outcome.command_id) reconciles the original operation.
```

For an already registered exact package, select `package_digest` instead of
`bundle`. Inline registration and first attachment are one database transaction.
The signed result contains the existing `instance_id`, `protocol_digest`, the
`package_digest` and `binding_created`. The operation creates no instance or
business record and changes no task state, grant, instance revision or body key.
It performs no journal replay.

Python uses the same operation:

```python
protocols = peerwork.ProtocolClient(kernel)
outcome = protocols.bind(
    workspace_id, instance_id, expected_protocol_digest,
    bundle=bundle, idempotency_key=stable_attachment_operation_id,
)
```

The native CLI accepts this request without a custom signature implementation:

```json
{
  "action": "structure.protocol.bind",
  "workspace_id": "WORKSPACE_ID",
  "idempotency_key": "STABLE_ATTACHMENT_OPERATION_ID",
  "body": {
    "instance_id": "EXISTING_INSTANCE_ID",
    "protocol_digest": "EXACT_EXECUTION_SHA256",
    "package_digest": "REGISTERED_PACKAGE_SHA256"
  }
}
```

```sh
peerwork kernel intent ORIGIN JOURNAL IDENTITY request.json
```

A replay of the original operation returns its original result. Selecting the
same package under another operation is a no-op (`binding_created: false`).
Selecting a different package on an already bound instance is refused with
`PROTOCOL_BUNDLE_ALREADY_BOUND`. A different execution digest is refused with
`PROTOCOL_BUNDLE_EXECUTION_MISMATCH`. Inline resources from a rejected transaction
are not retained. Revisions, keys, identity and task data are not migrated.

## Participant role and receiver selection

After successful attachment, each participant uses SDK 0.2.13 or later to resolve
its own existing role. The new SDK verifies the Owner's exact first-attachment
intent and its target instance, package and execution digests. Older bundle
verifiers do not understand this new source form; do not disable verification.

```javascript
const role = await protocols.role({
  workspace_id: workspaceId, instance_id: instanceId, role: selectedRole,
});
// Select package_digest from the verified result. Keep expected_origin,
// expected_actor, workspace_id, instance_id, protocol_digest and role explicit.
```

An existing grant must already include the selected role and action IDs. First
attachment adds neither permissions nor encrypted-key access. An Owner may
separately change a grant through the established signed API if that is intended.

Use the resulting exact binding with the
[delivery tools](agent-delivery.md). Run `doctor`, then `run`, under a private,
explicit receiver profile. A previous `REJECTED_NO_EFFECT` route claim is a known
refusal: it requires a new claim after repair, not indefinite replay. The receiver
clears a refused claim and prepares a new one on its next start. Preserve any
existing route/checkpoint state and follow its normal takeover/recovery rules.
A newly created subscription starts at the current frontier; it does not replay
past tasks or silently claim historical notification delivery.
