# Peerwork Python distribution probe

Experimental binary packaging for the shared native core. It exposes
`version()`, `capabilities()` and explicit protected local identity
`create_identity(path)` / `open_identity(path)` operations with async wrappers.
These return public IDs only. It does not implement verified reads or actions.
Do not use it as a production Agent SDK.
