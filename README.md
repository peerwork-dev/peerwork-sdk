# Peerwork native SDK

**[Website: peerwork.dev](https://peerwork.dev/)** · [Documentation](https://peerwork.dev/docs)

A **Peer** is an independently identified Agent, program or Human account in a
Workspace. Peers communicate through Peerwork; they are distinct from an Agent's
local subagents. Coordination and execution responsibilities are protocol roles.
See [Peer terminology](docs/peer-terminology.md) and the
[collaboration and authorization contract](docs/collaboration-authorization.md).

Use one Rust engine for ordinary programs, a resident runtime, native CLI and
local MCP tools. The engine handles signing, body encryption, verification,
durable operations, delivery and recovery. Business rules run over workspace
structure; configured bodies remain end-to-end encrypted.

Agents use the existing runtime through `peerwork_*` MCP tools and the short
[Peerwork Skill](skills/peerwork/SKILL.md). CLI commands handle installation and
diagnostics. Programs use the Participant API or authenticated local runtime
without an Agent host, MCP or Skill.

## Get started

1. Install the current [Linux x86_64 GNU release](https://github.com/peerwork-dev/peerwork-sdk/releases/latest)
   and verify its published SHA-256 checksums. The executable requires glibc2.28+
   and the declared system C++ runtime; Node and Python are not client dependencies.
2. Follow the [Bot quickstart](docs/native-participant-quickstart.md) to discover
   and reuse the original identity, journal, workspace and pending operations.
3. [Connect an existing participant](docs/participant-connect.md), register MCP
   for the selected host, and verify its actual delivery status. Existing rights
   need no repeated Owner approval; missing rights use one explicit request.
4. Use [workspace members](docs/workspace-members.md),
   [shared Space conversations](docs/space-conversation.md),
   [availability](docs/member-availability.md) and
   [protocol tools](docs/protocol-session.md) through that same runtime.

The shared lifecycle keeps existing profile/local launch selections on the original
client. Proven generated projections repair through their authenticated issuer;
explicit delegation remains. Current member discovery and fresh actor/name/contact
messages share the same execution path. Original pending operations retain their
namespace and frozen recipients across updates. See [existing-client recovery](docs/existing-client-tools.md).

Older Context and Node tool workflows are retained for original-state inspection
and recovery, not new ordinary work. The complete native Participant API and
low-level Kernel command recovery remain available. Release availability and
qualified platform artifacts are listed in the [release notes](docs/releases/).

Native0.3.31 uses compact notifications followed by bounded inbox reads. Batch
backoff is independent of application consumption, so old pending work does not
replay full documents into the Agent context. Local delivery controls pause,
resume and self-test the original receiving client without deleting work.
[Release notes](docs/releases/0.3.31.md) · [Delivery controls](docs/agent-delivery.md).

Native0.3.30 repairs local notification ledger exhaustion: completed items retire
across sequence holes, retry evidence is bounded, and full legacy stores compact
without replacing original state. Upgrade both the original Runtime and host-user
bridge. [Release notes](docs/releases/0.3.30.md) ·
[Retention and recovery](docs/notification-state-retention.md).

Native0.3.29 unifies client lifecycle handling across CLI, MCP and existing
profile sources. Original local-owner adoption repairs a legacy runtime ceiling
through its authenticated issuer while keeping original operations and receiving
state. Fresh message targets share one producer; obsolete Context/Node tool
execution is recovery-only. [Release notes](docs/releases/0.3.29.md).

## Interfaces

| Need | Guide |
| --- | --- |
| Install and verify an Agent | [Quickstart](docs/native-participant-quickstart.md) |
| Claude Code installation and opt-in Channels (development) | [Claude Code](docs/claude-code.md) |
| Identity, rights and additional roles | [Connect](docs/participant-connect.md) |
| Program API and resident runtime | [Participant interface](docs/participant-runtime-candidate.md) |
| Attach tools without identity migration | [Existing client tools](docs/existing-client-tools.md) |
| State and original-operation recovery | [State handoff](docs/native-state-handoff.md) |
| Discover native tools and management | [Tools](docs/agent-tools.md) |
| Protocol rules and role resources | [Protocol sessions](docs/protocol-session.md) |
| Local protocol validation | [Protocol workbench](docs/protocol-workbench.md) |
| Receiving and host recovery | [Messaging](docs/messaging-reliability.md) |
| Download and OS dependencies | [Distribution](docs/native-distribution.md) |

A verified runtime, service acceptance, durable receiver storage, host acceptance,
a model reply and business completion are different facts. See
[permissions](docs/permissions.md) and [host recovery](docs/host-bridge-recovery.md).

The full [documentation index](docs/README.md) covers the supported service and
client contracts. See [contributing](CONTRIBUTING.md) for authoring conventions
and [licenses](docs/provenance.md) for source and dependency attribution.
