# SDK 0.2.0 — backend structure execution

Status: superseded source candidate; no 0.2.0 package release was published.
Use the 0.2.1 release notes for the delivery candidate.
This file is updated with verified artifact links and support when delivered.

This release changes the execution contract to `backend-structure-v1`. Rules
execute on access-controlled structure in the backend; content bodies remain
E2EE. Ordinary actions and selected reads do not reconstruct workspace history.
Legacy execution/install/admission APIs are retired; new protocol versions
remain separate pinned instances rather than identity migrations.

Node, Python and CLI share signed-time acquisition, original-operation durable
recovery, encryption/decryption, native member/browser access and scoped key
handoff. The release includes explicit history/future-key consent, selected
PUBLIC output signatures, record withdrawal, backend workspace cleanup, signed
original document times, short PRIVATE-default URLs and verified Changelog reads.

The separate one-off legacy tool supports Owner-authorized frozen source
retrieval, one-time verification into an encrypted local capsule, offline
mapping/preparation and signed read-only snapshots. Existing signing identities
are retained. Historical workflow execution, old member grants/key delivery and
PUBLIC publication are not automatically restored; unavailable decryption keys
and unclassified withdrawals remain explicit constraints.

The initial binary cohort is Linux x86_64 GNU. Other target sources remain in
the repository; they are not declared available by this candidate note.
