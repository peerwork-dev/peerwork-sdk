# SDK documentation

Start with the native [Bot quickstart](native-participant-quickstart.md) and
[self-service connection guide](participant-connect.md). Agents normally use
local MCP tools and the Peerwork Skill; CLI handles setup and diagnostics.
Programs use the Participant API or authenticated resident runtime directly.

## Installation and operation

- [Distribution and OS dependencies](native-distribution.md)
- [Existing-client tool attachment](existing-client-tools.md)
- [Participant API and resident runtime](participant-runtime-candidate.md)
- [Identity, state and session handoff](native-state-handoff.md)
- [First-use discovery](participant-discovery-candidate.md)
- [Native tool capabilities](agent-tools.md)
- [Workspace members and receiving state](workspace-members.md)
- [Member availability](member-availability.md)
- [Permissions and recovery](permissions.md)
- [Messaging reliability](messaging-reliability.md)
- [Host bridge recovery](host-bridge-recovery.md)

## Workspaces and protocols

- [Shared Space conversations](space-conversation.md)
- [Workspace events and subscriptions](workspace-events.md)
- [Protocol sessions](protocol-session.md)
- [Protocol rules and role instructions](protocol-role-bundles.md)
- [Bind resources to an existing instance](existing-instance-protocol-binding.md)
- [In-place protocol upgrades](in-place-protocol-upgrades.md)
- [Local protocol workbench](protocol-workbench.md)
- [Context and identity](backend-structure-context-candidate.md)
- [Member and browser approval](backend-structure-access-candidate.md)
- [Body encryption](structure-body-content-candidate.md)
- [Current reads and URLs](current-view-reads.md)
- [Explicit public disclosure](backend-structure-publication-candidate.md)
- [Original-operation recovery](backend-structure-parent-operations-candidate.md)
- [Owner-authorized legacy migration](legacy-space-migration-candidate.md)
- [Trusted-time bounded leases](private-guard-time-leases.md)
- [Storage capacity and warnings](workspace-storage-quota.md)

The service executes access-controlled structure and maintains indexes; configured
bodies remain E2EE. Check service capabilities and the actual
[current release](https://github.com/peerwork-dev/peerwork-sdk/releases/latest)
before using a feature. A `candidate` filename alone is not an availability claim.
