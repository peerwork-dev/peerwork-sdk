# Installed host qualification

Run this suite in an isolated Linux TEST environment. It requires Python 3.11,
unprivileged network namespaces, PostgreSQL tools, Node, and a compiled product
fixture. Build the runtime test binary from the same SDK source as the installed
CLI being qualified (`cargo test --locked -p peerwork-runtime --lib --no-run`).
Provide exact versions of the host executables for the cases selected.

```sh
python3 tests/host-qualification/run.py \
  --sdk /path/to/installed/peerwork \
  --runner /path/to/peerwork_runtime-test \
  --product /path/to/compiled-product \
  --node /path/to/node \
  --postgres-bin /path/to/postgres/bin \
  --codex /path/to/codex \
  --opencode /path/to/opencode \
  --agy /path/to/agy
```

The default runs all cases. Repeat `--case` to select specific cases and omit
unused hosts. Pass `--postgres-library-path` for a relocatable PostgreSQL
distribution, or both `--runner-loader` and `--runner-libraries` for a test runner
with its own compatible loader. When launched as root, PostgreSQL runs as the
specified unprivileged `--postgres-user` (default `nobody`).

The runner creates a disposable PostgreSQL cluster accessible over a private Unix
socket. The test process, Peerwork service and harnesses run in a network namespace
with loopback only. Each run uses fresh home and state paths and deterministic
local models. The Rust cases create their own signed test identities, verify the
specific replies emitted by the harnesses, and retain the same session or route as
required by the case. The JSON output identifies the executable digests, case and
verified signed replies. Logs and transient state are removed on exit.

The cases cover compact receiver reconnect, Codex handoff and restart, and a
common signed-message flow with managed Codex plus either OpenCode V2 or AGY
ACP. The AGY runner provisions its own conversation through ACP and points the
Gemini provider at a deterministic loopback endpoint. Always select the host
version being qualified explicitly. An installed service or live user inbox
is never an input to these cases.
