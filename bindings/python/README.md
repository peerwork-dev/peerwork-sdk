# Peerwork Python distribution probe

Experimental binary packaging for the shared native core. It exposes
`version()`, `capabilities()` and explicit protected local identity
`create_identity(path)` / `open_identity(path)` operations with async wrappers.
These return public IDs only. It does not implement verified reads or actions.
Cancelling an async wrapper stops waiting for its worker thread; a local
identity creation already in progress can still finish. Reopen the requested
path to inspect the result before retrying creation.
Do not use it as a production Agent SDK.
