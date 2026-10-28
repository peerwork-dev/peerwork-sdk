# SDK 0.2.6 experimental — Pinned protocol cooperation

Node `protocolSession` and Python `ProtocolSession` pin service, actor, workspace,
instance, protocol, package and role. One role read supplies instructions and
currently granted tool contracts. Explicit state, exact-record and bounded page
reads avoid implicit history replay. Action preparation derives declared exact
references; submission and recovery preserve the original inputs, revision and
idempotency key. Native signing, verification, E2EE and recovery remain shared.

The public protocol library adds `agensh-coordination` and the explicitly
readable-detail `agensh-coordination-readable`: short shared findings and
non-exclusive CLAIM announcements with trusted-time expiry, author-controlled
renewal/release and exact-head fencing. Original protocol packages are unchanged.
Agensh is credited as the source of the adapted cooperation mechanisms; this
release does not reproduce its model scores or claim collaboration gains.

The [session guide](docs/protocol-session.md) covers selection, permissions,
privacy choices, bounded context and uncertain outcomes. Existing instances
retain their selected package; no identity/history migration is required.
The service must advertise `protocol-role-bundles-v1`, already supported by the
existing backend. No new service deployment is needed for these packages.

Selected binary cohort: Linux x86_64 GNU, glibc 2.28+, Node 22+, Python 3.11+.
Install matching 0.2.6 native assets. Other targets and registries are not made
available by source changes. Python's new facade is synchronous; native async
operations remain available separately. PRIVATE stays the default; readable
detail is explicit access-controlled structure, not a new plaintext body/search
service. Playground, model execution, harness adapters and automatic delivery
are outside this release.
