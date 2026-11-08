import test from "node:test";
import assert from "node:assert/strict";
import {
  cooperationProtocol,
  composeProtocol,
  sharedFindings,
  workClaim,
  reviewAdopt,
} from "../../examples/meta-protocols/index.mjs";
import { Scenario, token } from "../../examples/research/shared/scenario.mjs";
const A = token("alice"),
  B = token("bob"),
  H = "a".repeat(64),
  E = "b".repeat(64);
const fresh = () =>
  new Scenario(cooperationProtocol({ minLeaseMs: 10, maxLeaseMs: 1000 }));
const rejects = (fn) =>
  assert.throws(
    fn,
    /CONSTRAINT_FAILED|STALE_REVISION|FORBIDDEN|INVALID_PAYLOAD/,
  );
const take = (s, actor = A) => {
  s.execute(actor, "work.claim", { ttl_ms: 100 });
  return structuredClone(s.state.lease_ref);
};
const submit = (s, actor, claim) => {
  s.execute(actor, "work.submit", { claim_ref: claim, artifact_digest: H }, [
    claim,
  ]);
  return structuredClone(s.state.result_ref);
};
test("source modules compose to a bounded ordinary manifest; dependencies remain explicit", () => {
  assert.equal(cooperationProtocol().dependencies.length, 0);
  assert.throws(() => composeProtocol([reviewAdopt()]), /MISSING_MODULE/);
  assert.throws(() => composeProtocol([workClaim(), workClaim()]), /DUPLICATE/);
  new Scenario(composeProtocol([sharedFindings()]));
  new Scenario(composeProtocol([workClaim()]));
});
test("server time bounds leases; expiry/reclaim fence the old owner; submit consumes lease atomically", () => {
  const s = fresh();
  const a = take(s);
  rejects(() => take(s, B));
  s.now = 1100;
  rejects(() => s.execute(A, "work.renew", { ttl_ms: 100, claim_ref: a }, [a]));
  s.execute(B, "work.reclaim", { ttl_ms: 100 });
  const b = structuredClone(s.state.lease_ref);
  rejects(() => submit(s, A, a));
  const p = submit(s, B, b);
  assert.equal(s.state.work_state, "SUBMITTED");
  assert.equal(s.state.lease_holder, null);
  rejects(() => submit(s, B, b));
  assert.equal(
    s.records.get(p.record_id).structure.claim_ref.record_id,
    b.record_id,
  );
});
test("renewal requires current holder and increases expiry; releasing enables complementary work", () => {
  const s = fresh();
  const a = take(s);
  rejects(() => s.execute(B, "work.renew", { ttl_ms: 200, claim_ref: a }, [a]));
  rejects(() => s.execute(A, "work.renew", { ttl_ms: 100, claim_ref: a }, [a]));
  s.now += 1;
  s.execute(A, "work.renew", { ttl_ms: 200, claim_ref: a }, [a]);
  const newer = structuredClone(s.state.lease_ref);
  assert.notDeepEqual(a, newer);
  rejects(() => submit(s, A, a));
  s.execute(A, "work.release", { claim_ref: newer }, [newer]);
  take(s, B);
});
test("independent review binds exact proposal; stale review cannot approve a new result", () => {
  const s = fresh(),
    a = take(s),
    p = submit(s, A, a);
  rejects(() =>
    s.execute(
      A,
      "review.record",
      { proposal_ref: p, verdict: "PASS", evidence_digest: E },
      [p],
    ),
  );
  s.execute(
    B,
    "review.record",
    { proposal_ref: p, verdict: "PASS", evidence_digest: E },
    [p],
  );
  const old = structuredClone(s.state.review_ref);
  s.execute(B, "work.reopen", { result_ref: p }, [p]);
  const newer = submit(s, B, take(s, B));
  rejects(() => s.execute(A, "review.adopt", { review_ref: old }, [old]));
  s.execute(
    A,
    "review.record",
    { proposal_ref: newer, verdict: "PASS", evidence_digest: E },
    [newer],
  );
  const review = structuredClone(s.state.review_ref);
  rejects(() =>
    s.execute(B, "review.adopt", { review_ref: review }, [review], {
      roles: ["WORKER"],
      capabilities: ["CLAIM"],
    }),
  );
  s.execute(B, "review.adopt", { review_ref: review }, [review]);
  assert.equal(s.state.work_state, "DONE");
});
test("findings preserve author, admit challenges and protect current-version correction", () => {
  const s = fresh(),
    out = s.execute(A, "finding.publish", {
      kind: "FACT",
      subject: "interface",
    }),
    first = s.ref(out.produced_record_ids[0]);
  s.execute(B, "finding.challenge", { previous: first }, [first]);
  rejects(() =>
    s.execute(B, "finding.correct", { previous: first, kind: "FAIL" }, [first]),
  );
  const corrected = s.execute(
    A,
    "finding.correct",
    { previous: first, kind: "OBSERVED" },
    [first],
  );
  rejects(() => s.execute(A, "finding.retract", { previous: first }, [first]));
  const head = s.ref(corrected.produced_record_ids[0]);
  s.execute(A, "finding.retract", { previous: head }, [head]);
  assert.equal(s.records.get(first.record_id).structure.status, "ACTIVE");
  assert.equal(
    s.records.get([...s.heads.values()][0]).structure.status,
    "RETRACTED",
  );
});
