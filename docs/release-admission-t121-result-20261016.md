# T121 release admission correction

The unpublished `v0.1.0` workflow run `38835984112` stopped in
`actions/setup-python` before an SDK build on macOS ARM64 and Windows x64.
The official [actions/python-versions manifest](https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json)
was read as a 256-record JSON list (SHA-256
`3bffef7a0fddc945a17a5bb7b924462746844f4a39f7fdd57a318add7df13b21`).
Its `3.11.14` entry has Linux archives only. `3.11.9` is the newest stable
3.11 patch with Linux x64/ARM64, macOS x64/ARM64 and Windows x64 archives.

The seven `setup-python` uses in the reusable builder and release finalization/
publication workflow now pin `3.11.9`. The native matrix still has seven
targets and two unsigned replicas. Replica 1's existing installed-service gate
now receives `https://api.peerwork.dev` and `new-public-workspace` when the
corresponding repository variables are unset; explicit variable values still
override those defaults. The existing builder validates the HTTPS origin and
write scope. No service source assertion is invented when its optional commit
variable is absent. Version metadata was synced with the existing
`tools/release/version.py` to `0.1.1`, so a new immutable tag can carry the
fix without moving `v0.1.0`.

Focused checks passed: `version.py check --tag v0.1.1`, refusal of `v0.1.0`,
`service_gate_config` with the fallback values and missing/incorrect values,
static workflow counts/defaults/matrix checks, manifest platform checks, and
`git diff --check`. The broad offline `tests/release-tooling.py` and
`tests/release-workflows.py` suites were also attempted once and failed mainly
because their existing synthetic fixtures use `v0.0.1` against the current
root version (already `0.1.0` before this change); one tooling test lacked
`node` on the local PATH. Those runs are retained as failures, not passes or
evidence against the changed workflow configuration. No native build,
external-service workflow, publication or final-platform acceptance was run
in this correction package. A fresh `v0.1.1` provider run remains required.
