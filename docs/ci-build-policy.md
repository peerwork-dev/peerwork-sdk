# Native SDK build policy

Routine source validation and native release qualification use separate
workflows. CI configuration does not establish a published SDK version.

## Routine changes

`SDK checks` runs one Ubuntu x64 job for relevant main-branch pushes and pull
requests. Documentation-only Markdown changes are excluded. A newer commit
cancels an obsolete check for the same branch or pull request. The job checks
version consistency, Python/Node source syntax, release-source rejection and
packaging controls, and runs the locked Rust workspace tests. It does not
produce release artifacts or establish Windows/macOS compatibility.

Its cache contains Cargo registry/git data and debug build output, never local
identities, credentials or participant state. Keys separate OS, architecture,
Rust version, lockfiles, manifests, build scripts and pinned third-party inputs;
an exact source suffix allows later commits to restore a compatible earlier
cache and let Cargo revalidate changed sources. Pull request caches retain
GitHub's merge-ref scope; the native candidate uses a separate key namespace.

## Explicit native candidates

`Experimental native distribution` runs the complete eight-artifact matrix
only after either of these deliberate main-branch operations:

1. Run that workflow with **Run workflow**, selecting `main`.
2. Commit a new `.github/native-release-candidate.json` on `main`, for example:

   ```json
   {"version":"0.1.4","candidate":"lease-20261019-1"}
   ```

The version must match all package manifests. The candidate label is 1–80 ASCII
letters, digits, dots, underscores or hyphens; change it for a new candidate.
The actual source is the triggering commit, not a mutable version label. A
routine code or workflow commit does not launch the full native matrix.

This path preserves native GNU x64/ARM64, GNU 2.28 compatibility x64, musl
x64/ARM64, macOS Intel/ARM64 and Windows x64 artifact qualification. The pinned
containerized GNU compatibility and musl build procedures remain separate.
Host GNU, macOS and Windows jobs cache Cargo downloads and target output;
containerized jobs do not yet have new persistent caches. Candidate runs are
not automatically cancelled, so completed artifacts remain available for an
exact-source failed-job retry. Retry the failed job instead of rebuilding
successful platforms.

Mac builds set the deployment target before the first Cargo command: 10.12 for
Intel and 11.0 for ARM64, matching the prior experimental wheel defaults. The macOS candidate runs the complete Rust workspace tests with `--release`,
so their compatible dependencies can be reused by the CLI/Node release build;
routine Linux checks retain the debug-profile tests. Python compilation remains
under maturin: version 1.15 adds `-undefined dynamic_lookup` to the entire macOS
dependency graph through `CARGO_ENCODED_RUSTFLAGS`. That creates a genuinely
different build configuration. Its target outputs are cached alongside the
CLI/Node configuration; the CLI/Node linker settings remain separate. Merely
including the Python crate in the ordinary Cargo build would omit maturin's
required macOS link setup and is not used. Actual graph reuse and elapsed-time
savings still require the next native candidate; no measured macOS speedup is
claimed from a YAML change.

## Publication and existing candidates

The publisher accepts successful native main-branch `push` and explicit
`workflow_dispatch` cohorts from this repository and this exact native
workflow. It still requires all eight unique, unexpired artifacts and binds
the published source/tag/checksums to that run. A routine Linux check, fork,
pull request, tag-ref run, failed/partial cohort or substituted workflow is
rejected. Release assembly checks out the verified historical source SHA.

Sources explicitly withheld in `.github/experimental-release-holds.json` cannot
be published, even if all of their native builds succeed. The publication
validator reads that registry from the default branch before checking out a
historical source. Holds retain build evidence and leave other historical
qualified cohorts eligible; a successful build alone does not override final
acceptance.

This keeps older main-push candidates eligible for publication after selective
retry. SDK 0.1.4 source `fdb2f09f3eeead3fb19cc22f905c6e2066000b75`,
run `39268931251`, passed all eight targets after a selective macOS ARM retry
and is published as [v0.1.4-experimental.39268931251](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.1.4-experimental.39268931251).
The other seven accepted artifacts were retained. Anonymous GNU downloads
matched the previously accepted installed CLI, Python and Node packages.

The automatic publisher failed release creation with HTTP 403. The authorized
direct API fallback published the same verified cohort; this does not establish
that automatic publication succeeded. Historical commits whose workflow files
differ from the default branch require a release credential with Workflows
permission ([GitHub documentation](https://docs.github.com/en/rest/releases/releases#create-a-release)).
Actions retries separately require appropriate Actions write access. Preserve
the original failed operation and reconcile tag, draft and publisher status
before a manual handoff; do not rebuild successful targets to bypass a
publication-permission failure.

## Measured baseline and validation

The retained Intel job `118115788378` took approximately 34m27s: debug compilation
10m05s, CLI/Node release compilation 11m04s, Python release compilation 10m46s,
and approximately 28 seconds executing tests/doc tests. The same native
dependencies appeared in all three compile phases. Peak CPU/RAM were not measured. Inspection of the pinned
[maturin 1.15 source](https://github.com/PyO3/maturin/blob/v1.15.0/src/compile.rs)
confirmed its global macOS linker-flag injection; the original runner did not
record Cargo fingerprint diagnostics. Cache hit rates and actual time
savings require subsequent runner evidence.

Validate a policy change without launching a full matrix:

```sh
python tests/experimental-source.py
python tests/release-workflows.py
actionlint .github/workflows/checks.yml \
  .github/workflows/distribution-spike.yml \
  .github/workflows/publish-experimental.yml
```

These checks exercise rejected source/artifact combinations and release
packaging/signing boundaries with synthetic inputs. They do not substitute for
native artifact installation checks at publication.
