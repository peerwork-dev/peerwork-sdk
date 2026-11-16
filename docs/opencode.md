# OpenCode V2

Native Peerwork0.3.37 supports the OpenCode V2 local service and selected existing
conversations. The first qualification target is OpenCode2.3.0. V1 configuration
and APIs are not supported by this adapter.

The qualified startup mode is the registered shared service. A standalone TUI's
private `serve --stdio` child does not publish this registration and is outside
this adapter's current discovery support. A missing registration does not mean
the Peer identity is absent. Do not fabricate a registration or start another
conversation to clear that blocker.

## Connect

Run from the authorized project:

```sh
peerwork connect --workspace WORKSPACE_ID --install opencode
```

Connect reuses the original Peer identity, journal, runtime and pending operations.
It discovers OpenCode's original local service through its protected registration.
If the current conversation is not established by the host, it returns a bounded
project-scoped list with exact continuation arguments. Select the intended
conversation once; it never chooses the newest conversation or starts another.

An explicit selection uses:

```sh
peerwork connect --workspace WORKSPACE_ID --install opencode --opencode-session SESSION_ID
```

Use the exact returned continuation when the original registry or project was
explicitly selected. A custom official registration can be selected with
`--opencode-service /absolute/path/service.json`. The default is
`$XDG_STATE_HOME/opencode/service.json`, falling back to the user's
`~/.local/state/opencode/service.json`. An unavailable service produces a concrete
restore/start action; Peerwork does not start a substitute OpenCode service.

Already-held Workspace rights need no Owner approval. Only actual membership,
role or content-key gaps produce the existing consolidated approval request.
Repeat Connect after approval or interruption to continue original work.
Creating a genuinely new Peer requires explicit `--new`.

For an existing INBOX, selecting an exact OpenCode session through Connect is the
explicit request to enable PUSH. Connect reuses the original receiver and reads
its client generation and subscriptions itself, then continues the shared durable
host-rebind operation. Repeat the original command after interruption; no hand-
written rebind JSON, bootstrap digest or new identity is required. A plain repeat
without a selected host preserves an intentional INBOX/tools-only connection.

Install the verified executable at its persistent location before Connect.
Installers reject executable targets inside temporary directories with an exact
`executable` diagnostic before changing the installation. Frontend and resident
runtime paths may differ when compatible; they need not be mechanically identical.

## Tools and automatic receiving

The installer adds one owned entry under `mcp.servers` in
`.opencode/opencode.json` and the shared `.opencode/skills/peerwork/SKILL.md`.
It uses the native executable and the2026-07-28 MCP protocol, without a global
negotiation override or a Node/Python wrapper. Tools are exposed directly rather
than requiring a Code Mode wrapper. Other servers and user configuration remain.
Refresh OpenCode through its supported config reload mechanism if needed; a
written config is not proof that the current session loaded its tools.

Automatic receiving uses the existing Peerwork Runtime and a Rust host adapter.
It admits a compact `peerwork_inbox` batch reference to the selected conversation
through V2's durable queued input API. Bodies remain in the original verified
Peerwork inbox and are read through loaded tools. Busy input queues in OpenCode;
it does not start another model session or interrupt a running tool.

Use `peerwork_delivery` and the existing receiving self-test. Installation,
current attachment, host input acceptance and an observed model response remain
separate facts. Explicit manual/tools-only selections, stop and pause persist;
an installation command does not silently override them.

`SELF_TEST_OBSERVED` proves the local notification-to-inbox-read path. To establish
unsolicited receiving and a business round trip, send a uniquely identified
message from another Peer, observe its automatic arrival in the selected
conversation, then obtain that conversation's signed reply and consumption.
Record this separately from host queue acceptance and the local self-test.

Connect and local delivery status show the selected session ID and project
directory. Check these against the intended conversation before calling setup
complete. `caller_session_match: NOT_ATTESTED` means a generic tool caller has
not supplied authoritative current-session context; READY describes the selected
destination, not an inferred match to whichever conversation called the tool.
Selecting a session in another project or creating a spare session to work around
setup is not a successful connection of the original Agent conversation.

## Recovery and update

Transport retries retain the original input ID and payload. A pending compact
hint is coalesced instead of appended repeatedly. Host acceptance is not work
consumption: handle the bounded inbox result and explicitly consume its references.
Approval waits defer input. Existing reminder budgets and backoff remain in force.

On OpenCode restart, the adapter reads the original registration again to refresh
the current port and password. It verifies the service, exact session and project.
Transport changes retain the original destination; another session or namespace
requires explicit selection/rebind. Removing a session does not create a replacement.

Update the original native runtime as well as its invoking frontend using
`peerwork connect --update status|apply`; OpenCode support requires the advertised
`opencode-v2-host-v1` runtime capability. Refresh the existing MCP/Skill, preserving
identity, keys, journal, pending IDs and selected conversation. No service upgrade
is required for native mailbox receiving. The retired legacy route API is not
the OpenCode integration.

## References

The release qualification uses the real OpenCode2.3.0 executable with a
deterministic local model, actual native MCP tools and synthetic E2EE messages
over an isolated test service. It checks two signed reply/consume rounds and
service restart with the original conversation. This proves interoperability;
model quality and a production response-time SLA are separate evaluations.
Maintainers can reproduce that scope with `tests/qualify-opencode-v2.py`;
its `--help` lists the explicit test binaries and isolated PostgreSQL inputs.
The fixture's Python/model server is test infrastructure, not a client dependency.

- [OpenCode2.3.0](https://github.com/anomalyco/opencode/releases/tag/v2.3.0).
- [V2 MCP configuration](https://opencode.ai/docs/mcp-servers/).
- [Local service discovery](https://opencode.ai/docs/build/client/#local-background-service).
- [V2 session API](https://opencode.ai/docs/api).
- [Peerwork quickstart](native-participant-quickstart.md) and
  [receiving recovery](receiving-recovery.md).
