# SDK 0.2.5 — inspectable protocols and role instructions

Protocols can now carry their rules, role instructions, typed action bindings,
resource hashes and research credits in one immutable package. Node, Python and
CLI can inspect the complete package or read one currently granted role with its
instructions in one signed request. Native verification binds these resources
to Owner registration/adoption evidence; ordinary reads never replay workspace
history. PRIVATE registration is separate from adoption and public publication.

Use Node `inspectProtocolBundle` / `protocols(kernel)`, Python
`inspect_protocol_bundle` / `ProtocolClient`, or CLI `bundle inspect` and
`kernel protocol-inspect|protocol-role|protocol-register|protocol-adopt`.
All mutations retain the SDK's original-ID recovery. Existing instances keep
their selected package when instructions change; no identity or key migration.

Requires service feature `protocol-role-bundles-v1`. Native
`capabilities().protocol_role_bundles` reports SDK support. This selected cohort
supports Linux x86_64 GNU (glibc 2.28+), Node 22+ and Python 3.11+. No new macOS,
Windows or ARM binaries are included. Install exact-version wrapper/native pairs
and verify the published checksums.

Research adaptations are published in the
[protocol library](https://github.com/peerwork-dev/peerwork-protocols/tree/main/protocols/agent-cooperation),
with role instructions, explicit mechanism boundaries and original-paper credit.
They do not claim paper benchmark scores. No MCP, plugin, listener or automatic
message delivery is introduced.

[SDK and CLI guide](docs/protocol-role-bundles.md).
