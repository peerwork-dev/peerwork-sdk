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
evidence. Neither mypy nor pyright is installed or cached locally; a task-local
`pip install mypy` failed with `No matching distribution found for mypy`.
The `69c5a7d` fixture is syntax checked and source reviewed, but its real
static-consumer result remains unverified until the configured Linux jobs run.

The accepted host-built CLI, Node addon, and Python extension each require up
to `GLIBC_2.38`; `readelf` on the CLI finds `__isoc23_strtol` and
`__isoc23_sscanf` at that version. Both unresolved references trace to
`f8e4fd781484bd36-bcm.o` in the built `aws-lc-sys` crypto archive. This
identifies the host build's dependency origin, not a defect proven in an older
glibc build. The existing workflow pins a manylinux 2.28 image digest and
checks the emitted binaries' maximum GLIBC version, but that job has not run.

The local container bundle includes Buildah 1.39.3 and a VFS image store, even
though no Docker/Podman command is on PATH. A bounded read-only image list under
approved local execution found no pinned manylinux digest. The first exact
digest pull failed because the bundled `containers.conf` points to an old
helper path; a task-local corrected config reached the next setup failure:
Buildah could not find a signature policy at its system/user default paths.
An existing policy copied to a task-local XDG config did not change that lookup.
No system policy was modified and no registry/auth conclusion follows from
these pre-network failures. The pinned glibc 2.28 build/install gate is still
unverified; the practical next route is the configured CI container job or a
task-local old-glibc sysroot/toolchain that recompiles all native dependencies
and passes the same binary symbol and installed-consumer checks.
