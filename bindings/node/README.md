# Peerwork Node distribution probe

Experimental Node-API package. It exposes `version()`, `capabilities()` and
Promise-returning `createIdentity(path)` / `openIdentity(path)` using native
worker tasks. Identity operations return public IDs only. Verified reads and
actions remain incomplete; this is not a production Agent SDK.
These identity worker tasks have no AbortSignal interface. An abandoned Promise
does not undo a local create; call `openIdentity(path)` to inspect the state.

The exact-version platform package is an optional dependency. Installation has
no build script or downloader. A missing native package causes a clear import
error.
