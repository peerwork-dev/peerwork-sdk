# SDK 0.1.6 experimental — safe coordination marker migration

This candidate adds the Owner migration support absent from the 0.1.5
experimental cohort. It archives completed `coordination_intents` only after
matching the authenticated Owner, item, signed operation and reconstructed input
hash. Dispositions retain their expected-version binding. Recovery-excluded
commits cannot establish completion.

Packetless unproven markers remain durable as `RETAINED_UNRESOLVED`, including
an unsent `send` whose plaintext is not recoverable from its hash. Explicit
Python, async Python, Node and CLI retirement uses the exact attachment/marker
and expected input hash, records `RETIRED_LOCAL`, and performs no network POST.
Migration, retry and local retirement do not invent delivery or cancellation.

The [migration guide](docs/owner-migration.md) documents the three dispositions,
source protection, original-packet recovery and current limits. Matching old
reminders remain ambiguous and retained. Foreign or malformed source markers
refuse; pending signed packets retain their original recovery path. Nonempty
SQLite `client_operations` and unresolved specialized installation work remain
separate migration boundaries. The 0.1.5 guard-time and SQLite v2 compatibility
fixes are retained. No service deployment or ownership transfer is required.

The affected scripted acceptance reproduces two completed ACK markers, two
completed disposition markers and one packetless send using genuine TypeScript
clients. It compares the exact prior cohort with the corrected native code,
checks source removal/fresh handles, archive proof references, hash-pinned local
retirement and zero new commit POSTs. Installed Python, Node and CLI acceptance
and published artifact checks are separate release gates; source notes alone do
not establish downloadable availability.
