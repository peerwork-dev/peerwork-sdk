# T065: repeated conversion eligibility

**The proposed repeated-conversion amplification route is unsupported by current reference f828. No fixture or API call was started.** A completed secure PRIVATE workspace cannot be converted again to PRIVATE v2 (or PRIVATE v1), and PRIVATE→PUBLIC is also refused. This finding is specific to the conversion route; it is not a universal >64 MiB history impossibility claim. The larger-history witness remains open.

The public method `SecureAgentClient.convert` (`workspace-secure-agent.ts:765–767`) delegates to `convertSecureWorkspace`. For a new conversion with a verified source, `workspace-secure-conversion-client.ts:26` first requires wire v1/v2, then requires **source visibility PUBLIC and target PRIVATE**; otherwise it throws `CONVERSION_WIRE_UNSUPPORTED` or `CONVERSION_UNSUPPORTED`. The target-policy construction at43 preserves `verified.policy.payload.v` rather than selecting a new wire version, and increments the epoch for the permitted PRIVATE transition. The public method has no arbitrary version/epoch override.

The service independently enforces the source boundary. `workspace-secure-store.ts:656–660` accepts only authorization wire v1/v2 and requires an existing secure source to have both workspace and secure-state visibility PUBLIC, state ACTIVE, exact Owner, current sequence/head, signed authorization and target-policy binding. A completed PRIVATE state fails `SECURE_CONVERSION_NOT_FOUND` before any new source snapshot/stages. This check is independent of a proposed target wire version. PRIVATE→PUBLIC also fails; it must not be invented as a declassification or amplification step.

An exact existing authorization-hash retry returns the existing conversion status (`store:657`), after comparing the saved target policy and original source checkpoint. That is idempotent recovery of the same conversion, not permission to create another archive or add stages. New conflicting authorization goes through the source-visibility gate. The previous conversion's ACTIVE_PRIVATE status alone is not reconversion authority.

There is a supported, **different** PRIVATE v1→v2 structure upgrade (`workspace-secure-agent.ts:89–113`). It retains visibility/epoch and adds structure policy plus `secure.structure.begin/page/end` **ADMIN** commits through ordinary `/commits`; it does not make MIGRATE archives or invoke the conversion activation exception. Format upgrade v1/v2→v3 at732–744 is likewise an ADMIN transition, preserves visibility/epoch, and makes further conversion explicitly unsupported. Neither is a demonstrated route to repeatedly re-archive prior MIGRATE wires. No larger-history bound is inferred from their names or from the global storage allowance.

Consequently there is no eligible tiny repeated-conversion chain whose new wire sizes/counts/fragment limits should be measured for this hypothesis. T055's genuine legacy PUBLIC→signed PUBLIC→PRIVATE chain remains accepted as one finite two-stage route; it cannot be repeated from its PRIVATE result. No writer sampling, bulk history, source quota/limit change, unsigned history, old runtime, database seeding, SDK build or new product capability was used. Existing T050/T053/T055 failures/results and T063's local archive acceptance are unchanged.

This read-only package is based on SDK52a1f100. T064 received the exact existing T063 server/consumer seams, same profile/DB/origin/known receipt seed, original attachment ID and already-removed-source status directly; this task did not build or run their installed candidate. Ledger start12:57:28 UTC; eligibility source finding sent12:59:09, before the3-minute checkpoint. Source investigation ended by13:01; no service/runtime test timings exist to report. One documentation path is delivered; main is untouched pending acceptance.

Exact reference commit: `f828b6c50a0a58d1e718af90f653b214adcc3328`. Named source SHA-256 values follow:

- src/workspace-secure-agent.ts: `93e77302998bfb48d5b1fffad384ccdc3b122263e1e41afade2dc10ba8d14429`

- src/workspace-secure-conversion-client.ts: `150342c2daf5ad3f59de57a99e7aa5f3fec1ee2744cf34686810d3ede886cddd`

- src/workspace-secure-store.ts: `61033155cfb0b042497703a39329e1d981d571ba9c87e5b8eabd3d8c01643dd0`
