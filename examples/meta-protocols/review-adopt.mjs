// SPDX-License-Identifier: Apache-2.0
import {
  literal,
  body,
  state,
  actor,
  ref,
  payload,
  eq,
  not,
  set,
  produced,
  permission,
  schema,
  exact,
  append,
  action,
} from "./dsl.mjs";
/** This module consumes work-claim's explicit work.result/state contract. */
export function reviewAdopt() {
  const proposal = ref("proposal_ref", "work.result"),
    review = ref("review_ref", "review.result");
  const guards = [
    ...permission("REVIEWER", "REVIEW"),
    eq(state("work_state"), literal("SUBMITTED")),
    eq(body("proposal_ref"), state("result_ref")),
    not(eq(payload(proposal, "author"), actor)),
  ];
  const reviewEffects = (verdict) => [
    append(
      "review.result",
      {
        author: actor,
        proposal_ref: proposal,
        verdict: literal(verdict),
        evidence_digest: body("evidence_digest"),
      },
      { slot: "review", relations: [{ kind: "reviews", target: proposal }] },
    ),
    set("review_ref", produced("review")),
    set("work_state", literal(verdict === "PASS" ? "REVIEWED" : "OPEN")),
  ];
  return {
    id: "review-adopt",
    requires: ["work-claim"],
    initial_state: { review_ref: null, adoption_ref: null },
    roles: ["REVIEWER", "INTEGRATOR"],
    capabilities: ["REVIEW", "ADOPT"],
    schemas: {
      "review.result": schema({
        author: "string",
        proposal_ref: "json",
        verdict: "string",
        evidence_digest: "string",
      }),
      "review.adoption": schema({
        author: "string",
        proposal_ref: "json",
        review_ref: "json",
      }),
    },
    actions: [
      action(
        "review.record",
        {
          proposal_ref: exact("work.result"),
          verdict: { type: "enum", values: ["PASS", "FAIL"] },
          evidence_digest: { type: "source_sha256" },
        },
        [],
        [],
        {
          reads: ["work_state", "result_ref"],
          writes: ["review_ref", "work_state"],
          variants: ["PASS", "FAIL"].map((verdict) => ({
            when: [...guards, eq(body("verdict"), literal(verdict))],
            effects: reviewEffects(verdict),
          })),
        },
      ),
      action(
        "review.adopt",
        { review_ref: exact("review.result") },
        [
          ...permission("INTEGRATOR", "ADOPT"),
          eq(state("work_state"), literal("REVIEWED")),
          eq(body("review_ref"), state("review_ref")),
          eq(payload(review, "verdict"), literal("PASS")),
          eq(payload(review, "proposal_ref"), state("result_ref")),
        ],
        [
          append(
            "review.adoption",
            {
              author: actor,
              proposal_ref: payload(review, "proposal_ref"),
              review_ref: review,
            },
            {
              slot: "adoption",
              relations: [{ kind: "adopts_review", target: review }],
            },
          ),
          set("adoption_ref", produced("adoption")),
          set("work_state", literal("DONE")),
        ],
        {
          reads: ["work_state", "review_ref", "result_ref"],
          writes: ["adoption_ref", "work_state"],
        },
      ),
    ],
  };
}
