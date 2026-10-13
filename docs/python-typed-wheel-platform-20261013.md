# Typed Python wheel and Linux baseline checkpoint

The Python package has inline public annotations but the accepted pending-stage
wheel omitted `peerwork/py.typed`. Commit `2ad7ff1` adds the empty PEP 561
marker and checks it in the existing distribution jobs. Commit `69c5a7d`
adds a Linux x64/arm64 CI consumer that installs the wheel in a fresh venv,
then runs mypy against a positive `IdentityInfo`/identity-signature example
and a wrong-argument negative. The negative must report an `int` passed where
`create_identity` requires `str`, while `reveal_type` must not be `Any`. This
checker job is configured but has not run. It adds a CI development tool, not
a package runtime dependency. The checker fixture is
`tests/verify-installed-python-types.py` (SHA-256
`2a9afd7b32d36dea4a9a1c7724379ad8f2c8366212651b9a40066c30642a913b`).

The immutable native input for a local Python-only packaging overlay was the
pending-stage `222859d` source archive
`.build-artifacts/pending-stage-222859d/sdk-222859d.tar` (SHA-256
`d27bae33cd5c140158685fd03d8103c704675e0fa9bb51277c0532f2bbd55885`).
The overlay source has the same 374 archived files plus the empty marker; it
does not contain the later orphan-stage source from main `5d2e25a`. The original
wheel is retained unchanged at
`.build-artifacts/pending-stage-222859d/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl`
(SHA-256 `837ca33a34f6232e144f6294a79c46ec0333465ea2796f1fa4edf23e8d443502`).

Using the existing release target and offline Cargo inputs, a Maturin release
wheel build from the overlay's `bindings/python` directory exited 0 in session
`77956`. The new wheel is
`.build-artifacts/typed-python-2ad7ff1/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl`
(SHA-256 `90fc772b623d30a6d06764d73d6bc837f68c1c7d8091a54cf5d1c8056f2ef4ee`).
Its build log is `.build-artifacts/typed-python-2ad7ff1/build-wheel.log`
(SHA-256 `a204a77d548616c65f67c04e96ff29e89b9d8808128aaf53fa2fe2995b6ebf53`).
Wheel member comparison found only the added marker and changed `RECORD` and
CycloneDX source-path metadata; the native extension is byte-identical in both
wheels (SHA-256 `afd0c16e1fe5baac27e69497aec2326c93816661d60cbc23e50b4cb7d5cea26d`).
All nine hash-bearing `RECORD` entries verified; the `RECORD` self-entry has no
hash. `tests/verify-typed-wheel.py`
accepted the new wheel and rejected the original wheel with
`wheel omits peerwork/py.typed`.

A fresh offline venv installed the new wheel in session `94438` (exit 0),
confirmed the marker through `importlib.resources`, and imported the annotated
public identity signatures. Its log is
`.build-artifacts/typed-python-2ad7ff1/install.log` (SHA-256
`98b2ba10e449fbc4dd57ef901326f2ab35c542da97698cbe11a199861725eb56`).
Runtime `get_type_hints` confirms annotations exist, but is not static checker
evidence. At that checkpoint neither mypy nor pyright was installed or cached locally; a task-local
`pip install mypy` failed with `No matching distribution found for mypy`.
The `69c5a7d` fixture is syntax checked and source reviewed, but its real
static-consumer result was then unverified; the later local result is recorded below.

The accepted host-built CLI, Node addon, and Python extension each require up
to `GLIBC_2.38`; `readelf` on the CLI finds `__isoc23_strtol` and
`__isoc23_sscanf` at that version. Both unresolved references trace to
`f8e4fd781484bd36-bcm.o` in the built `aws-lc-sys` crypto archive. This
identifies the host build's dependency origin, not a defect proven in an older
glibc build. The existing workflow pins a manylinux 2.28 image digest and
checks the emitted binaries' maximum GLIBC version, but that job has not run.

The worktree already contains a native manylinux 2.28 rootfs under
`.build-artifacts/glibc28/bundle/rootfs`. The earlier
`docs/distribution-spike-20261012.md` checkpoint records full manifest/layer
SHA checks against the exact workflow image digest and a passed installed
Python/Node/CLI service gate on older SDK source `7831650` plus the separately
tested GNU ICU PIC correction `6596631`. An approved local `unshare`/`chroot`
probe of that rootfs again returned `glibc 2.28`. That prior success proves a
usable local baseline route, but it does not transfer to the current `222859d`
wheel or the newer Owner attachment APIs.

Before locating the existing unpacked rootfs, a bounded Buildah image-list
probe found no pinned image in its VFS store. An unnecessary exact-digest pull
attempt first failed on a stale bundled helper path, then on absent signature
policy at Buildah's system/user default paths. A task-local XDG policy copy was
ignored; `buildah --signature-policy ...` returned `unknown flag`. No system
policy was modified, no network pull was reached, and these setup failures do
not negate the independently SHA-verified unpacked rootfs. The next relevant
gate is one immutable current-source native build inside that rootfs, followed
by binary symbol checks and installed consumers. The configured CI job also
remains unrun.

## Local static consumer follow-up

The earlier `No matching distribution found for mypy` result was caused by
the filesystem sandbox's DNS failure to reach `pypi.org`, observed explicitly
as `Name or service not known` before any package-index response. An approved
task-local public-PyPI check listed `mypy`, and `mypy==1.18.2` (the version
pinned in `.github/workflows/distribution-spike.yml`) installed into
`.build-artifacts/typed-python-2ad7ff1/typecheck-venv` in session `89954`
(exit 0). Its package freeze is
`.build-artifacts/orphan-glibc28-1fbe859/static-checker-freeze.txt` (SHA-256
`444cff272ddcb23444bab40868677c787e0998c0866b1542ba76c4e0ffe00fd6`).
No package runtime dependency changed.

A fresh host-Python 3.11 task-local venv installed the unchanged current glibc 2.28 wheel
`.build-artifacts/glibc28/bundle/rootfs/work/sdk-orphan-1fbe859/dist/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl`
(SHA-256 `1cc86214748a838e29b9ae378dc54a9d42f912fae16a43bc277a4e65f4564706`)
using `pip install --no-index --no-deps` in session `80412` (exit 0), with
`peerwork/py.typed` present. The installed import and marker resolved under
`.build-artifacts/orphan-glibc28-1fbe859/type-consumer-venv/lib/python3.11/site-packages/peerwork/`;
the checker itself resolved under
`.build-artifacts/typed-python-2ad7ff1/typecheck-venv/lib/python3.11/site-packages/mypy/`.
The actual static check command was
`python3 tests/verify-installed-python-types.py --python .build-artifacts/orphan-glibc28-1fbe859/type-consumer-venv/bin/python --mypy .build-artifacts/typed-python-2ad7ff1/typecheck-venv/bin/mypy`.
It exited 0 in session `38640`; log
`.build-artifacts/orphan-glibc28-1fbe859/static-consumer.log` has SHA-256
`6a269353c3524e3a5661a51746c8875521c3d5690ac26e84ea29700ac03a73fd`.
The fixture SHA-256 is
`2a9afd7b32d36dea4a9a1c7724379ad8f2c8366212651b9a40066c30642a913b`:
strict mypy reports a non-`Any` public `create_identity` type in the positive
case and rejects an integer where `create_identity` requires `str` in the
negative case. This is one installed Linux x64 wheel consumer check; the
configured Linux x64/arm64 static-check CI jobs remain unrun; this does not
establish macOS or Windows typing/package behavior. The earlier 2.38 typed
overlay wheel also passed the same fixture locally in session `97582`, without
changing the current glibc 2.28 artifact.
