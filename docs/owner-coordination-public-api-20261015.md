# Dedicated Owner coordination API

Enable built-in coordination on an existing workspace selected from protected ordinary Owner history. The runtime selects its PUBLIC or PRIVATE binding; callers do not supply visibility, material, manifests or grants. Generic protocol installation remains unavailable for this dedicated flow.

Python `SecureOwnerWorkspaceClient` exposes `enable_coordination(workspace_id, *, version=None, participants=None)`, `resume_coordination(workspace_id, begin_command_id)` and `coordination_operations(workspace_id)`, with matching `_async` methods. Node's `openSecureOwnerWorkspaces` exposes `enableCoordination(workspaceId, input?, {signal}?)`, `resumeCoordination(workspaceId, beginCommandId, {signal}?)` and `coordinationOperations(workspaceId, {signal}?)`.

Version omission defaults to v1; request `version=2` / `{version:2}` explicitly for v2 or the supported v1-to-v2 upgrade. Omitted participants stay omitted: a new installation uses the Owner, while an already-enabled preset receives no requested-participant grant check. An explicit empty list requests the Owner and is checked on the already-enabled path too. Caller-supplied participant actor IDs must be unique, already-signed workspace members; enabling coordination does not admit new members. These remain explicit choices; these facades invent no grant or material input.

Each enable/resume call advances at most one durably saved step. A `PENDING` result includes the original `begin_command_id`; retain it, or discover protected local operations on a fresh handle, then resume that same BEGIN. A step command ID is not a replacement BEGIN. `ACCEPTED` follows signed ACTIVE verification. An already-enabled result can have a null BEGIN when no native operation was necessary. Operation history alone does not refresh remote acceptance. Python async cancellation uses the existing signal-and-worker-drain contract, then raises `CancelledError`; inspect history on a fresh handle before continuing. Node forwards `AbortSignal` to the same native cancel handle.

CLI commands (each also accepts `--help` without configuration or network access):

```text
peerwork secure owner-coordination-enable CONFIG_JSON_FILE WORKSPACE_ID INPUT_JSON_FILE
peerwork secure owner-coordination-resume CONFIG_JSON_FILE WORKSPACE_ID ORIGINAL_BEGIN_COMMAND_ID
peerwork secure owner-coordination-operations CONFIG_JSON_FILE WORKSPACE_ID
```

Enable input examples are `{}` (v1, omitted participants), `{"version":2}` (v2, omitted participants) and `{"version":2,"participants":[]}` (explicit Owner participant request). Use a protected input file and preserve the returned original BEGIN. Enable accepts only `version` and `participants`; unsupported versions, malformed participants and unknown fields refuse through the typed boundary.

`OwnerCoordinationProgress` preserves status, workspace/version/protocol digest/instance and nullable original BEGIN, step command/action, accepted sequence/head/policy hash. Errors retain the runtime's safe code/message through each facade. This API does not expand capability flags or claim installed/platform/Agent coverage; those require the separately recorded gates.
