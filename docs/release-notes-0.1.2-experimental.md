# Peerwork SDK 0.1.2 experimental candidate

Published: [v0.1.2-experimental.39199024029](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.1.2-experimental.39199024029). Source
`1ee448b56feeac40b3ac385c79ab4942d033d7d8`; all eight native target jobs passed.
Ten public assets include eight target ZIPs, SHA256SUMS and SOURCE.json. This is
an experimental prerelease, not a stable or PyPI/npm registry publication.

This release moves repeated Agent mechanics into a shared Rust runtime used by
Python, Node and the standalone CLI:

- Explicit existing-member context binding pins identity, service, workspace
  and profile continuity without copying keys or substituting Owner authority.
- Generic protocol discovery, exact source/reference description, member actions
  and original-operation recovery preserve verified command/effect evidence.
- Native PRIVATE [workspace-browser approval](browser-approval.md) validates the
  request, creates delegation/encrypted key delivery and recovers the same saved
  approval; no TypeScript checkout/helper is required.
- A durable action-receipt inbox provides independent consumers, leases,
  redelivery, local acknowledgement, cancellation and native bounded waiting.
  This inbox currently supports Unix (Linux/macOS) only. Windows event storage
  deliberately returns `UNSUPPORTED_PLATFORM`; a Windows package build does not
  imply event-delivery support. The context descriptor exposes
  `events.platform_supported` independently of its stable binding fingerprint.
- An unchanged-checkpoint probe avoids transferring unchanged commit history.
  Backlogs over 256 receipts progress in bounded batches with exact verified
  partial cursors rather than permanent batch-size backpressure.

Local acceptance before version synchronization: five affected core checks,
25 runtime checks, installed Python/Node/CLI discovery/events and native browser
approval/recovery regressions passed. A separately frozen CLI Agent trial passed
business correctness and workflow after a preserved model-capacity interruption
and stale-lease recovery; it was not an uninterrupted first-attempt pass.
These records do not qualify every distribution target or the revised default
entry guide. Native CI results must be assessed separately for this release.

Explicit limits: only existing admitted PRIVATE contexts and ACTION-receipt
events are covered. Changed history still uses full replay; true incremental
verification, additional platform/admission producers, new-member cold start,
executable continuation resume and broader event sources remain unfinished.
The inbox retains at most 10k events/64MiB without automatic pruning. Offline
queues cannot establish fresh revocation. Approval acceptance and actual browser
consumption are distinct. No fleet-scale or universal platform workflow claim.

See the [implementation/evidence checkpoint](sdk-agent-runtime-implementation-20261019.md)
and [verified-delta plan](sdk-verified-delta-plan-20261019.md).
