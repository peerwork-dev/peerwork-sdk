# SDK 0.2.4 — storage diagnostics and early warnings

Resource/quota HTTP 429 responses now preserve their resource error code instead
of being reported as request-frequency `RATE_LIMITED`. Pending mutations remain
`UNKNOWN` without a verified receipt, retain the original command ID and can be
resumed after capacity becomes available. Repeated automatic retry is not
recommended for quota exhaustion. Unverified HTTP diagnostics never finalize an
operation or override signature verification.

With service capability `workspace-storage-warnings-v1`, authorized workspace
metadata reports logical storage usage, configured limits, ordinary-write
headroom and remaining capacity. Node and Python emit a warning when a workspace
enters the warning or critical level; the CLI prints a warning to stderr while
retaining structured JSON on stdout. Warning thresholds are 80% and 95% of
ordinary write capacity. Other verified responses also carry near-limit
warnings. Identity, encryption and protocol permissions are unchanged.

This selected release supports Linux x86_64 GNU (glibc 2.28+), Node 22+ and Python
3.11+. Download the wheel, Node packages or CLI with their published checksums.
No macOS, Windows or ARM binaries are published in this cohort.

[Storage capacity and warnings guide](docs/workspace-storage-quota.md).
