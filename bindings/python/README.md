# Peerwork Python distribution probe

Experimental binary packaging for the shared native core. It exposes
`version()`, `capabilities()` and explicit protected local identity
`create_identity(path)` / `open_identity(path)` operations with async wrappers.
These return public IDs only. `KernelClient` exposes configured-origin discovery,
exact saved command preparation, pending/status lookup and signed-receipt-bound
kernel command results. The caller supplies the full kernel command object;
the native core validates and signs it, and signed packets remain private.
The command actor and audience must match the local key and pinned discovery;
authority must match the client's configured digest. By default that digest is
SHA-256 of the local actor ID, matching the TypeScript client's default.
Catalog chunk commands use `prepare(command, upload_chunk=bytes)`; the shared
core checks its byte length and signed digest before saving exact bytes.
Verified secure-agent reads and actions remain incomplete.
Cancelling an async wrapper stops waiting for its worker thread; a local
identity creation already in progress can still finish. Reopen the requested
path to inspect the result before retrying creation. The kernel async methods
pass cancellation into native discovery/HTTP and drain the worker before
returning cancellation. A submitted command can already have committed at
the service when cancellation arrives; reopen the journal, check
`status(command_id)`, and exact-retry the saved ID if it remains pending.
Do not use it as a production Agent SDK.
