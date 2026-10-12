# Peerwork Node distribution probe

Experimental Node-API package. It currently exposes only `version()` and
`capabilities()` from the shared Rust core. It does not implement verified
reads or actions and must not be treated as a production Agent SDK.

The exact-version platform package is an optional dependency. Installation has
no build script or downloader. A missing native package causes a clear import
error.
