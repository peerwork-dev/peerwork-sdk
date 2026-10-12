# Kernel intent journal checkpoint, 2026-10-12

This is a bounded runtime checkpoint for the TypeScript `WorkspaceClient`
command path. It does not implement network submission, signed receipt
acceptance, or the separate secure-agent action intent path.

## Pinned source and behavior

The accepted tracked TypeScript source at `dd8a9d2` / evidence `4065739`
uses `clients/secure-workspace/source/src/workspace-client.ts` for SQLite
`client_intents` (SHA-256
`e63ca81a92fa5a94f023cae8ed31c806e7bfac1a2989a3371731b58f0d0227c2`).
It persists the exact signed command before POST, reuses an identical
`command_id` only when the stored command matches, and marks accepted only
after a command-bound signed receipt/result check. Its secure-agent packet and
action intent path is distinct: `workspace-secure-intents.ts` SHA-256
`3650a1a6bcfec34a48f56704ac05aeec5dc167a6497778ec9486a5455e1a2dc7`,
with protected state and local locks in `workspace-secure-local-state.ts`
SHA-256 `b5795d7fd3730c1c2deb2d00576c1715e1b838397b6ed8de05112f6ee99f8316`.

The Rust `KernelIntentJournal` currently stores exact signed JWS and exact
HTTP request bytes in a bundled SQLite database. Its only state is `PENDING`.
The public listing contains a command ID, digest, and creation time; it does
not return the saved JWS or request body. An existing ID with different bytes
returns `IntentConflict`. The native schema has a distinct application ID;
opening an old TypeScript store fails closed with `IncompatibleStore`, pending
an explicit backup/readback migration. The parent directory and database file
must be private and owned by the current Unix user. SQLite uses an immediate
transaction for initialization and preparation, WAL mode, and `synchronous=FULL`.

## Local verification

`cargo test -p peerwork-runtime --offline --locked` passed 4/4 on Linux
x86_64. Tests exercised restart with exact saved bytes, same-ID same-byte
idempotence, different-byte conflict, old-store refusal, insecure-directory
refusal, and two separate test processes racing on one command ID. One process
prepared its bytes and the other observed conflict; the surviving row retained
the exact corresponding request. The first old-store test failed because its
synthetic database fixture was created with mode 0644 and correctly hit the
file-permission guard before the schema check. After setting that fixture to
0600, the intended incompatible-schema check passed. This correction does not
change production behavior.

## Open gates

Preparation accepts opaque signed bytes for local storage only; no transport
API sends them. The core must supply a typed verified command/result receipt
before a future transition to `ACCEPTED`. HTTP status alone is insufficient.
Raw wire bytes remain intact so the core's lossless UTF-16 parser can verify
valid escaped surrogate input. Secure-agent signed packet intents and their
separate protected state, acceptance from exact journal/control evidence,
restart/retry orchestration, and old-store migration remain open. Windows
protected state opening currently fails closed until ACL handling is
implemented and tested on a real Windows runner. No full SDK capability is
claimed from this local store checkpoint.
