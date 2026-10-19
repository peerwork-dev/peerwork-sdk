# Peerwork SDK 0.1.3 experimental candidate

Status: source candidate; native CI, public release artifacts and final installed
artifact acceptance are pending. The currently published build remains
[0.1.2 experimental.39199024029](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.1.2-experimental.39199024029).
A source version or local package build is not a public release.

This candidate adds bounded PRIVATE current-page reads through the shared Rust
engine and Python, Node and CLI interfaces. `CurrentPageClient` uses an existing
active protected profile and the SYSTEM-maintained readable structure projection.
It verifies pinned service query/checkpoint evidence, Owner policy, selected
original author signatures and required guard-time evidence, then decrypts
selected content locally. No Owner publisher adoption or raw-key input is needed.

Results report `SERVICE_STRUCTURE_SELECTION`: selection and completeness rely on
the pinned service, while selected content and attribution are independently
verified. These are read-only results; they do not establish full historical
semantic validity, activate keys or authorize writes. Pages have explicit object,
commit, byte and time bounds. Pagination binds the checkpoint and query; changed
checkpoints require restarting the page sequence. Missing keys, unsupported
sources or failed proofs produce errors without a hidden full-history fallback.

Additional interfaces generate PRIVATE-by-default workspace/browser links and
read the official public Changelog with pinned signed-journal verification.
Changelog limits bound returned entries, not history transfer. Separate optional
`PublicReadViewClient` and `PrivateReadViewClient` retain explicit Owner-publisher
adoption and `AUTHORIZED_STATE` assurance; they are not the default PRIVATE path.

See [current-page usage and limits](current-view-reads.md) and
[trusted time and lease support](private-guard-time-leases.md). This candidate
adds no bounded-duration lease extension, public native Owner guard-time
activation facade, automatic signer-key rotation, incremental event replay or
new Windows durable event-inbox support. Ordinary audit/write/read/watch paths
retain their existing full verification requirements.

Publication must use one successful eight-artifact native CI run, with matching
source/version metadata, public checksums, and installed Python/Node/CLI
qualification from the produced artifacts. Platform success and actual public
asset URLs will be recorded after those gates pass. Publication to GitHub
experimental releases does not imply a stable release or PyPI/npm registry upload.
