# T115 first release version preparation

Prepared release identity `0.1.0` (`v0.1.0`) in an isolated worktree from SDK `72f0b417ea1fc2e9338d4e35ea4e62ee95b43140`. Used the existing `tools/release/version.py sync --version 0.1.0`, then `tools/release/version.py check --tag v0.1.0`.

The version authority is `[workspace.package].version` in `Cargo.toml`. The tooling synchronized the five local Cargo.lock workspace entries and the Node wrapper plus all seven platform optional dependencies. Python derives its version dynamically from Cargo. The focused check passed and reports package names, seven targets, workspace crates and exact tag. `git diff --check` passed. No build or artifact was run; existing `0.0.1` accepted binaries remain tied to their original source and are not relabeled. Final artifacts must be rebuilt from the selected version before release.

Anonymous version metadata lookup for `peerwork-sdk` on PyPI and `@peerwork/agent-sdk` on npm was unavailable: the public-page fetch returned cache misses and direct unauthenticated registry requests failed DNS resolution (curl exit 6). This does not establish that `0.1.0` is unused or that either namespace is owned. The version is prepared locally only; registry ownership, collision status, access and publication remain unverified. No tag or remote write was made.
