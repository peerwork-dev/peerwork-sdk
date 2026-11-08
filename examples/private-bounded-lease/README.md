# Bounded PRIVATE lease example

This is a generic platform exercise, not an application task-dispatch protocol or a permission template. It creates a new synthetic PRIVATE structured workspace and gives its Owner the example's sole role. Choose application roles, membership, business actions and downstream fencing separately.

The complete [manifest](manifest.json) has four actions: `lease.claim`, `lease.renew`, `lease.reclaim`, and `lease.use`. The proposed `expires_at` is an encrypted input and is copied into state; effects never read time. At the service's signed transaction admission time **T**, claim/renew/reclaim require:

```
time_add(T, 1000) <= body.expires_at <= time_add(T, 60000)
```

Both TTL endpoints are inclusive. Renewal additionally requires `T < old.expires_at`, the current holder and generation, and a strictly increased expiry. Reclaim requires `T >= old.expires_at`, the expected old generation, and a strictly greater new generation. Use requires the current holder/generation and `T < expires_at`. Every operation also retains the ordinary signed source checkpoint/CAS checks. Consumers outside this protocol must enforce the generation themselves; this example cannot fence external side effects.

## Run with the installed Python SDK

The directory setup and end-to-end example are qualified on Linux. Windows
requires private ACL setup; this script does not provision Windows ACLs.
Native package platform support is separate from this example setup.

Install the qualified **0.1.4 experimental** wheel for your Python/platform from the exact release linked by [the public guard-time guide](https://peerwork.dev/docs/private-guard-time). The guide must name the release tag and artifact hash; an unqualified source build is not that release.

```sh
python3 -m pip install --only-binary=:all: "$PEERWORK_SDK_0_1_4_WHEEL"
```

With that `peerwork-sdk` **0.1.4** artifact installed, the standalone [Python example](run.py) uses only the native SDK and Python standard library. Download `run.py`, `closure.json` and `package-pins.json` together from the [public example directory](https://peerwork.dev/docs/examples/private-bounded-lease/README.md). No product checkout, Node, compiler or PEM import is needed at execution time:

```sh
for file in run.py closure.json package-pins.json; do
  curl --fail --silent --show-error --output "$file" \
    "https://peerwork.dev/docs/examples/private-bounded-lease/$file"
done
```

```sh
python3 run.py --origin "$PEERWORK_ORIGIN" \
  --audience "$PEERWORK_AUDIENCE" --service-key "$PEERWORK_RECEIPT_KEY" \
  --state-dir /absolute/path/to/new-native-owner-state
```

Loopback development additionally requires `--allow-loopback-http`. The example preflights pinned discovery and the exact service expression profile before creating state. Native state owns identity, encryption history, package installation and signed operation persistence. Its `example-progress.json` records creation, installation, guard activation and action IDs. On a pending/uncertain failure, use those IDs with `owner.resume`, `installer.continue_install`, `guard.resume` or `actions.reconcile`; do not start a new owner or re-sign a changed lease. If an exception occurred before returning an ID, the native `operations()`, `installs()`, `history()` and `pending()` collections retain recoverable state.

The [complete closure](closure.json) includes `protocol.source.json`, a positive `time_ms` fixture and the exact release lock. The platform source build generated this closure and verified its compiled protocol digest before emission. This is ordinary protocol composition and installation, not a privileged lease-specific SDK wrapper.

## Separate platform TypeScript example

The platform source repository also contains a TypeScript implementation and
runner. Those build tools and source files are not part of this native SDK
checkout. See the [platform guide](https://peerwork.dev/docs/private-guard-time)
for that alternative; no published TypeScript npm package is implied. The
Python example above runs using this checkout's included files and the installed
native SDK alone.

## Verification

The platform source test `tests/workspace-secure-bounded-lease.test.ts` uses actual HTTP and signed service attestations. It checks both TTL boundaries and their adjacent milliseconds, renewal before/at expiry, reclaim before/at expiry, nonincreasing expiry, stale generation, lost accepted response followed by reopening and exact-intent recovery, checkpoint substitution, and attestation tampering. The interpreter tests separately exhaust comparison orientations, nested additions and safe-integer overflow. Time-derived effects remain unsupported.
