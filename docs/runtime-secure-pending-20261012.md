# Secure pending journal boundary, 2026-10-12

The TypeScript `SecureAgentClient` has a separate secure packet/action-intent
path from its `WorkspaceClient` command-receipt SQLite path. The native
`secure_intents` module now stages an internal, pending-only durable store for
that path. It uses the same protected filesystem lock and atomic replacement
as secure local state, but a distinct file and schema. Each row pins the
configured origin and local actor at store level, and its own intent ID,
secure route, action, workspace, owner key, requested intent digest, SHA-256
of exact request bytes, and exact base64url-encoded packet. An exact repeated
prepare is idempotent; the same ID with changed bytes or context fails.
Untrusted exact HTTP response bytes can be appended in a bounded observation
list, including after an uncertain POST, without changing the row's pending
classification. Public summaries contain only ID, workspace, action, and
observation count; no raw packet or response is a language DTO.

Opening a saved store rejects a changed origin or actor, unsupported schema,
duplicate JSON keys, malformed base64, changed packet digest, excessive size,
or invalid row metadata. One Linux Rust 1.89 locked-offline regression passed:
exact packet and an unverified 2xx-looking response survived process-style
close/reopen; repeated prepare and duplicate response were idempotent, changed
packet same ID conflicted, and changed origin/actor refused. This is storage
evidence only. No secure packet is currently submitted from the public SDK;
the HTTP status and stored response cannot authorize `ACCEPTED`.

Before a production secure submit or retry, core must provide a private
constructor proof over the exact saved packet signature, schema, actor,
workspace, route, owner/discovery context, and local intent digest. Runtime
must compare every proof field with this immutable row before transport.
Before any terminal result, a separate core `VerifiedSecureOutcome` must
authenticate the complete signed policy/commit chain, sealed content and
recovery/migration restoration, protocol source/structure, ACTION evaluator,
and exact response/head/effect binding. Runtime then compares that proof to
the unchanged row and persists the terminal state atomically. These proofs,
actual secure HTTP loss/restart and cross-platform execution remain open.
