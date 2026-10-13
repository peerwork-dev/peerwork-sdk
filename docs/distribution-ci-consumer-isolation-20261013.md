# Distribution CI offline npm consumer isolation

Workflow source `03b19d5`, corrected at `50e69cbbae93ad62664ea473c80f6ea3c56f00d6`, gives each of the five `npm install --prefix dist/node-consumer` steps a minimal task-local private `package.json` before installation. The steps are Linux GNU x64/arm64 (Bash), GNU 2.28 x64 (Bash inside its pinned image), Alpine musl x64 (sh inside its pinned image), macOS arm64/x64 (Bash), and Windows x64 (PowerShell). This prevents npm from resolving an unrelated parent project/workspace when the consumer directory has no package manifest, as observed earlier in installed test setup (`docs/public-admission-installed-20261013.md` and `docs/native-public-catalog-installed-20261013.md`, first `ENOTDIR` attempts). The correction changes only `.github/workflows/distribution-spike.yml`; it does not alter built SDK packages.

The first `03b19d5` review found a real nested-shell quoting failure: single quotes in the GNU 2.28 and musl manifest commands broke the outer host-quoted container scripts. At `50e69cb`, a bounded no-network check extracted both workflow container commands, ran each outer Bash command with a stub `docker`, and captured the actual argument vector. Both produced one intact inner script argument (10 total arguments), retained their `npm install` and final CLI commands, and passed the respective `bash -n` or `sh -n` parse. Executing the captured manifest-generation lines in separate task-local directories produced the exact JSON object `{ "name": "peerwork-offline-consumer", "version": "0.0.0", "private": true }` in both cases. `git diff --check` also passed. These checks did not execute either image or its package build.

On local Linux, the following equivalent consumer command used the already built immutable `a0908ee` facade tarball SHA-256 `24b09218a3f83a2ef2729f2515f181d3236346200486e435f41123bf3ad207d9` and platform tarball SHA-256 `1efb2acf8ab6419bacbdd2a0d330bc9204cacd44c5a1b8bb3ce174449c6166d9`; it exited 0 and `offline-smoke.mjs` returned native version/capabilities:

```sh
mkdir -p .build-artifacts/platform-consumer-check/dist/node-consumer
printf '%s\n' '{"name":"peerwork-offline-consumer","version":"0.0.0","private":true}' > .build-artifacts/platform-consumer-check/dist/node-consumer/package.json
PATH=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin:$PATH npm install \
  --prefix .build-artifacts/platform-consumer-check/dist/node-consumer \
  --offline --ignore-scripts --no-audit --no-fund \
  --cache .build-artifacts/platform-consumer-check/npm-cache \
  .build-artifacts/private-stage-a090/source/bindings/node/peerwork-agent-sdk-0.0.1.tgz \
  .build-artifacts/private-stage-a090/build/platform/agent-sdk-linux-x64-gnu/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz
PATH=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin:$PATH node \
  bindings/node/scripts/offline-smoke.mjs .build-artifacts/platform-consumer-check/dist/node-consumer
```

This was one Linux local package installation and native version/capability smoke, not an Agent workflow test or execution of the five GitHub jobs. The repository configures `macos-15`, `macos-15-intel`, and `windows-2022` package jobs, but this host is Linux x86_64 and has no local `gh`, `pwsh`, or `xcrun` executable. Prior HTTPS push and SSH read probes lacked credentials; no new auth attempt or remote workflow run occurred. Actual macOS and Windows build, installed import/API, dependency, protected-state and cancellation evidence remain release gates.
