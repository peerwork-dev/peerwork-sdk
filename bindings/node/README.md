# Peerwork Node distribution probe

Experimental Node-API package. It exposes `version()`, `capabilities()` and
Promise-returning `createIdentity(path)` / `openIdentity(path)` using native
worker tasks. Identity operations return public IDs only. `openKernel()`
anchors discovery to an explicit origin and exposes exact saved command
preparation, pending/status and signed-receipt-bound kernel results. Signed
packets remain private. Verified secure-agent reads and actions remain
incomplete; this is not a production Agent SDK.
The command actor/audience must match the key/discovery, and authority must
match the configured digest (default SHA-256 of the local actor ID).
For a catalog chunk command, pass `{uploadChunk: Buffer | Uint8Array}` to
`prepare`; the shared core checks byte length and digest. The facade rejects
non-finite numbers, undefined members, sparse arrays, accessors and non-plain
objects before JSON serialization so JavaScript coercion cannot silently
change the command that is signed. It rejects proxies and serializes a fresh
snapshot of validated data properties, so getters or inherited `toJSON`
cannot change the checked value during serialization.
These identity worker tasks have no AbortSignal interface. An abandoned Promise
does not undo a local create; call `openIdentity(path)` to inspect the state.
Kernel methods accept an AbortSignal and propagate it into native discovery
and HTTP. An aborted submitted command can already have committed remotely;
reopen and check its saved status before exact retry. Dropping a Promise
without aborting its signal does not cancel its native worker.

The exact-version platform package is an optional dependency. Installation has
no build script or downloader. A missing native package causes a clear import
error.
