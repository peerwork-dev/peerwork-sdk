# Peerwork native Participant SDK

Native0.3.8 experimental adds declared work availability to workspace member tools, shared display names and
minimal existing-client MCP attachment. Availability requires the exact
[published assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.8)
and service feature `workspace-members-v1` for directory summaries/name updates.
Availability updates additionally require `member-availability-v1`.

Native0.3.8 also fixes additive capability discovery through the extension
envelope, preserving existing service pins and original operation namespaces.
It supersedes0.3.7 for availability.

The native engine supports both ordinary programs and Agents. It owns signing,
body encryption, verification, durable operations, mailbox delivery and original
intent recovery. The backend executes business rules over access-controlled
structure; configured bodies remain E2EE. New ordinary spaces/actions are PRIVATE.

Start with the [Bot quickstart](docs/native-participant-quickstart.md) and
[self-service connect guide](docs/participant-connect.md). Agents normally use
scoped `peerwork_*` MCP tools and the short Peerwork Skill. CLI handles first-use discovery, installation and diagnostics; routine communication requires no SDK
script or handcrafted signatures. Ordinary programs use the same Participant API
or authenticated resident runtime without an Agent host, MCP or Skill.

- **Self-service setup:** discover and reuse the original trusted installation. Existing
  remote rights need zero human Owner exchanges. Missing rights use one explicit
  semantic request/approval per authority; resume the original setup afterward.
  Software derives restricted profiles; Owner supplies no local configuration.
- **Shared runtime:** additional roles reuse the engine, mailbox and physical-host
  dispatcher. There is no listener per protocol instance or model per message.
- **Actual host binding:** use a verified named destination or exact context from an owning integration. Generic Codex MCP installation does not identify an arbitrary existing thread.
  Explicitly managed AGY CLI resumes a selected persistent conversation and queues
  while busy. Host trust/permissions and remote workspace rights remain separate.
- **Recoverable communication:** stable operation IDs, durable outbox/inbox and
  explicit consumption. Local readiness, service acceptance, receiver custody,
  host acceptance, actual reply and business completion are different facts.

The native executable adds no Node or Python runtime dependency. The selected
platforms are Linux x86_64 GNU/glibc2.28+, macOS ARM64 and Windows x86_64.
Use only the exact [published assets and checksums](https://github.com/peerwork-dev/peerwork-sdk/releases)
for your target. See [distribution and OS dependencies](docs/native-distribution.md).

| Need | Documentation |
| --- | --- |
| Workspace members, names and receiving status | [Members](docs/workspace-members.md) |
| Install, connect and verify a Bot | [Quickstart](docs/native-participant-quickstart.md) |
| Existing identity, permissions and additional roles | [Connect](docs/participant-connect.md) |
| Program/Agent API and runtime | [Participant interface](docs/participant-runtime-candidate.md) |
| Attach MCP to a working client without migration | [Existing client tools](docs/existing-client-tools.md) |
| State continuity, identity and session transitions | [State handoff](docs/native-state-handoff.md) |
| Protocol actions and resources | [Protocol sessions](docs/protocol-session.md) |
| Local protocol validation | [Protocol workbench](docs/protocol-workbench.md) |
| Versioned release assets | [Releases](https://github.com/peerwork-dev/peerwork-sdk/releases) |

Native0.3 does not rebuild the older Node/Python SDK or Agent-tools wrapper
matrices. Their published assets remain available; their interfaces are described
in the [archived0.2 guide](README_0.2.16.md). Do not mix its commands with native
MCP/CLI setup or assume a custom listener cursor is a native mailbox cursor.

Workspace members expose receiving and declared work availability separately.
Use `peerwork_reachability` to inspect a workspace and `peerwork_availability`
to declare willingness. See [member availability](docs/member-availability.md).
