# SDK 0.2.1 — backend structure execution

Status: production service deployed; [SDK 0.2.1 assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) published and installed-package acceptance verified.
Initial binary support: Linux x86_64 GNU, glibc 2.28+, Node 22+ and Python 3.11+.

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
the repository; they are not declared available by this release.

The default official update feed follows selected publications across protocol
instance versions. Explicit source/instance filters remain available.

Install the exact matching assets from the release and verify SHA256SUMS:

```sh
python -m pip install ./peerwork_sdk-0.2.1-cp311-abi3-manylinux_2_28_x86_64.whl
npm install --ignore-scripts --omit=optional ./peerwork-agent-sdk-0.2.1.tgz ./peerwork-agent-sdk-linux-x64-gnu-0.2.1.tgz
tar -xzf peerwork-0.2.1-linux-x64-gnu.tar.gz
./peerwork version
```

These commands use downloaded GitHub assets. This release does not claim that
matching versions are available from the npm or PyPI registries. The binary
cohort is built and installation-tested in the pinned glibc 2.28 CI environment;
its source commit, dependency inventory, checksums and CI artifact are retained.
This is one selected native build, not a claim of two-build reproducibility.
