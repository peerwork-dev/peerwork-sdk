# Composable coordination protocols

These source modules produce ordinary `backend-structure-v1` manifests. The
backend enforces their readable business structure; bodies remain E2EE. They
require the current Backend execution profile and SDK 0.2.4 or later for the
[runnable research examples](../research/README.md).

```javascript
import {composeProtocol, workClaim, reviewAdopt, sharedFindings}
  from './examples/meta-protocols/index.mjs';

const manifest = composeProtocol([
  sharedFindings(),
  workClaim({minLeaseMs: 1000, maxLeaseMs: 600000}),
  reviewAdopt(),
], {name: 'my.cooperation', version: '1.0.0'});
```

Composition happens at source level, before signing/adoption. Duplicate module,
action, schema or state names and missing module dependencies are rejected.
The result has no unresolved package dependencies. Combining arbitrary modules
still requires checking their declared state and authority contracts.

| Module | Actions | Enforcement and ownership |
| --- | --- | --- |
| Work claim | `work.claim`, `work.renew`, `work.reclaim`, `work.release`, `work.submit`, `work.reopen` | One work item per instance. Backend time bounds TTL. The exact current claim reference fences prior holders, including after renewal. Submitting a result consumes the claim atomically. Reopening requires INTEGRATOR/REOPEN. |
| Shared findings | `finding.publish`, `finding.correct`, `finding.retract`, `finding.challenge` | Any granted worker can publish. Only its author can correct or retract the selected current version. Peers can append a challenge. Old evidence remains verifiable. Retraction is a logical status change, not physical deletion or PUBLIC withdrawal. |
| Review/adopt | `review.record`, `review.adopt` | Requires the work-claim module in the same manifest. A different author reviews the exact current result. Only a granted integrator can adopt the current PASS review. |

A claim expires at `server_time + ttl_ms`. Renewal requires an unexpired current
claim and strictly later expiry; reclaim requires server time at or beyond the
old expiry. Clients can use a local clock to decide when to try, but cannot
make a lease valid by changing that clock. Submission, review and adoption
check current state and revision in the transaction. Historical exact references
alone do not establish current dependency freshness.

Findings can live in a separate shared board. A work item's claim, result,
review and adoption stay in one instance so their transition is atomic. This
example uses a known pair of work scopes; it does not put an organization's
entire task queue into one instance or scan retained history to find work.

Encrypted narratives, patches and review evidence are separate body artifacts.
Structured fields contain author IDs, labels, state, exact references and hashes.
The backend validates authority, transitions and reference binding. It cannot
judge a patch's correctness or inspect an encrypted test report. The worker's
independent evaluator supplies that verdict; granting a reviewer role expresses
trust in its judgment.

The research setup grants both peers WORKER, REVIEWER and INTEGRATOR capabilities
for a symmetric demonstration. Review must still be by a different author. A
production application should select reviewer/integrator identities explicitly;
these roles confer no workspace administration or implicit membership.

Run offline enforcement and recovery tests with Node 24:

```sh
node --test --test-isolation=none tests/research/protocols.test.mjs tests/research/host.test.mjs
```
