# Unreleased: original local component recovery

Ordinary MCP reads reuse the selected original registry directory and read its
latest atomic snapshot. They no longer reopen onboarding discovery and XDG
association storage on every request. Replaced directories, changed private
permissions and identity mismatches remain rejected.

Path errors retain structured reasons across asynchronous calls. Local MCP
responses include safe component metadata and a diagnostic ID; owner-local
stderr and the ordinary Agent CLI identify the exact failed path without
credentials or private message contents. Missing, inaccessible, unprotected,
malformed and oversized endpoint files have distinct error codes.
Path faults no longer terminate MCP before protocol startup. Its tool catalog
and structured diagnostics remain available while the original component is
repaired; no private operation bypasses the failed check.

Persistent local configuration faults report BLOCKED with their diagnostic and
repair action. Repeated unchanged startup failures are coalesced. After a
targeted repair, the existing original startup interpreter can continue without
a new Peer, Connect operation, host rebind or identity/journal replacement.
Explicit stop and pause remain authoritative. No service update is required.

These changes are a source candidate, not part of the published0.3.38 archive.
Existing Peer installations have not been modified or declared recovered.
