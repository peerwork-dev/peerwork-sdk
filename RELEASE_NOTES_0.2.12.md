# SDK 0.2.12 experimental — Existing-instance protocol bundle attachment

Adds Owner-authorized first attachment of an immutable role bundle to an existing
bare-manifest instance, through Node `protocols.bind`, Python `ProtocolClient.bind`
and native CLI intents. Inline package registration and attachment are atomic.
The package must preserve the instance's exact execution digest. Existing tasks,
instance state/revision, member grants, identities and E2EE keys remain intact;
no task/history migration or replay is performed. An existing binding cannot be
replaced. Original-operation recovery and same-package no-op retries are retained.

The native verifier authenticates the exact Owner attachment source, including
its target instance and both digests. Participants reading this new source form
need SDK 0.2.12+. Existing grant and role checks still apply. The server must
advertise `owner-protocol-bundle-binding-v1`; no database schema change is needed.

Protocol-selection refusals now carry signed, precise error codes, including
`PROTOCOL_BUNDLE_NOT_BOUND`, instead of an unstructured HTTP 404 that looked like
an unknown transport outcome. The [attachment guide](docs/existing-instance-protocol-binding.md)
covers Owner preparation, participant reads and delivery receiver restart.

Selected release assets: Linux x86_64 GNU, glibc 2.28+, core Node22+/Python3.11+;
receiver Node24. No other-platform or registry publication is claimed.
