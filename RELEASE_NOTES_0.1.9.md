# Native SDK 0.1.9 experimental

Develop protocols locally with the installed Python, Node or CLI package, and
recover invitation completion through the existing pinned Agent Context.

* Build deterministic synthetic fixtures, simulate actions with the real native
  evaluator, and inspect state, effects and exact failing constraints without a
  service or identity. Export selected verified PRIVATE instance state once to
  test against existing data. No private keys are exported.
* Keep old and new protocol instances on their pinned versions. Optional ticket
  conversion uses explicit business actions and source revisions. Generate a
  fixed plan, revalidate it online, and resume the same durable operation by ID
  after uncertainty. The SDK retains the original plan; callers do not need to
  reconstruct its packets or preserve an executable request themselves. Dependency changes stop with `PLAN_STALE`; already accepted
  effects remain visible if the predicted frontier differs.
* Complete guarded PRIVATE invitations with guard context bound before encryption
  and signing. Recover a committed operation after a lost response. Older native
  missing-guard finalize packets can receive one explicitly authorized successor
  only after authenticated intrinsic-inadmissibility and history checks. Original
  packets and identity remain intact.
* Inspect local producer compatibility, reject unknown declared activation
  requirements, and receive structured, privacy-preserving rejection diagnostics
  instead of an unexplained HTTP status.

See [the workbench guide](docs/protocol-workbench.md) and
[offline example](examples/protocol-workbench/offline.py). Existing Owner/member
import interfaces remain available independently of protocol publication.

Experimental GitHub assets are separate from stable PyPI/npm publication. A local
simulation is not a receipt. Cross-instance execution is not atomic, and separate
copied stores do not provide distributed exactly-once processing. Composed or
unresolved dependency manifests and related legacy execution-proof families are
explicitly outside the initial workbench projection; unsupported input is refused.
Guarded producer coverage is scoped to the declared native paths, not every
external client or arbitrary old saved packet.
