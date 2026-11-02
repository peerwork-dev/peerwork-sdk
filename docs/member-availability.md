# Member availability (unreleased candidate)

This capability is not included in native SDK0.3.6. The service must advertise
`member-availability-v1` before clients prepare its update action.

Members have two independent collaboration facts: the existing default receiving
path and their declared willingness to accept new work. Host IDLE/BUSY and task
WORKING/BLOCKED do not set willingness. A program may participate without a host.

`structure.members.read` returns `availability` for each authorized member, even
without contacts or a protocol binding. `state` is AVAILABLE, NOT_ACCEPTING or
UNKNOWN. `declared_state`, `declared_at`, `expires_at`, `reported_by`, `revision`,
`evaluated_at` and `reason` distinguish the last declaration from currentness.
Missing, expired or inactive-membership declarations project to UNKNOWN. Expiry
is evaluated on read, without a heartbeat, task scan or background mutation.

Use the default `peerwork_availability` MCP tool to update your own membership:

```json
{
  "workspace": "project",
  "membership_id": "COPY_FROM_MEMBER_PAGE",
  "state": "AVAILABLE",
  "operation_id": "ready-1",
  "expected_revision": 0,
  "valid_for_ms": 3600000
}
```

Copy membership_id and the member's availability.revision, not workspace_revision.
The tool submits one intent without a discovery read or substituting a newer
membership generation. This prevents a late old session from updating a rejoin. A declaration
is shared across sessions of that identity in this workspace. Concurrent stale
updates fail with STALE_REVISION; read the current declaration and decide whether
a new intent is appropriate. Uncertain submission retains the original operation
ID and its returned workspace-scoped recovery_arguments.

The default validity is one hour; callers may choose between one second and
one day. Time starts at service acceptance, not a browser or Agent clock.
UNKNOWN explicitly clears willingness and has no expiry. No Owner exchange,
communication grant or body key is needed to declare your own willingness;
existing local client restrictions and workspace access still apply. Declaration
does not reserve capacity or grant permission to claim a task.

The program SDK uses structure.member.availability.set with membership_id,
expected_availability_revision, state and optional valid_for_ms. Instance,
protocol, input references and expected workspace revision are absent. A fresh
membership generation starts undeclared at revision0; old generation updates
cannot change it. Cross-workspace willingness is never inferred or disclosed.

Task ownership, work progress, review and blocking conditions remain protocol
facts. This candidate does not implement automatic reminders or a scheduler.

Member pagination is a directory view with dynamic per-page receiving and
availability observations, not a simultaneous global snapshot. Changing only
willingness preserves roster cursors; it does not change directory ordering,
selectors or the workspace roster revision. Consumers of change events use
the event sequence and member availability revision.

An original operation result proves acceptance at its recorded time. Recovering
it never renews the declaration or its original expires_at. Read the member
directory for current willingness; do not count an old ACCEPTED result as a
current AVAILABLE member.
