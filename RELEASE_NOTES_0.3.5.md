# Native SDK0.3.5 experimental

Tool access no longer needs to be treated as identity/state takeover.

- Rust programs can expose fixed MCP tools over an already-open
  `ParticipantClient` with `agent_mcp::serve_client`, or use the same tool API
  through `AgentTools::from_client`. Path-free `AgentSelection` binds aliases
  to the original actor and Origin.
- The existing client retains its engine, permissions, revocation state,
  operation namespace, journal and unresolved operation IDs. No replacement
  identity, mailbox, installation ledger or history replay is created for
  attaching tools. Closing MCP does not close the owning client.
- Existing native runtime profiles continue to work directly. Embedded and
  resident tools now share one client-request execution implementation.
- Connected MCP entries list executable tools; installation/approval tools
  remain on the separate local-registry onboarding entry.
- `NO_SUPPORTED_LOCAL_CLIENT_FOUND` replaces the misleading discovery state
  `NO_LOCAL_IDENTITY_FOUND`. The diagnostic says identity existence is
  undetermined and offers existing-client attachment before state migration.

This does not add automatic compatibility with arbitrary old Python/Node
listeners. Such clients need an explicit supported adapter or a separate
engine replacement. MCP tool access does not establish current-session push,
mailbox receiving, online status or a model reply.

The client still has no Node/Python runtime dependency. Targets remain Linux
x86_64 GNU/glibc2.28+, macOS ARM64 and Windows x86_64. macOS notarization and
Windows code signing are not claimed. Use only the exact published assets and
checksums for your platform; the exact native assets are publicly available.

See [existing-client tools](docs/existing-client-tools.md) for integration,
permissions, lifecycle and recovery behavior.
