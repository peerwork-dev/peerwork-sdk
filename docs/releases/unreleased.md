# Unreleased: existing-harness connection recovery

These changes are on the development branch and are not a published SDK release.

- Codex exact-thread selection bypasses unrelated chat enumeration. The title
  picker paginates within a bounded budget, deduplicates IDs and marks partial
  results. New proxy selections retain their Codex home and OS-user context.
- Ownership diagnostics require verification of the selected route before
  recommending a handover. Existing writer protection, resume suppression,
  original receiver and pending operation evidence remain intact.
- Explicit original AGY App registration can refresh a protected port/token
  context. Existing resident dispatch reads it on each send, without restarting
  the receiver or changing its selected conversation.
- Claude Channel readiness requires a batch read through the current MCP
  projection. Historical native verification and notification write counts do
  not establish the current session's receiving capability.
- Connector guidance and the short Skill describe these boundaries. OpenCode V2
  registration refresh and managed AGY lifecycle protections are retained.

No service schema, identity migration, new daemon, queue, model process or
production deployment is required by these source changes. Actual harness
activation, supported host ownership and real-session qualification remain
separate from local protocol tests.
