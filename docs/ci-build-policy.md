# SDK build policy

Routine checks and native release qualification are separate. Source checks run
for affected changes; native qualification is explicitly selected and builds only
Linux x86_64 GNU. Do not rebuild retired language-binding or platform matrices.

Use the pinned Rust toolchain, locked dependencies and shared compilation cache.
Caches never replace compilation, installed-process checks, source identity,
ABI inspection or license collection. Repeat semantic tests only when affected
code or unresolved evidence requires them. Preserve the actual outcome of a
failed run; do not relabel it as a pass.

Normalize compiler paths before packaging. Public source, logs, metadata and
archives must contain only distributable source and user-facing documentation.
Keep operator reports, private environment details and internal execution
records outside this repository.
