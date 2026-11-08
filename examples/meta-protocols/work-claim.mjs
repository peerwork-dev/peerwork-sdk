// SPDX-License-Identifier: Apache-2.0
import {
  literal,
  body,
  state,
  actor,
  time,
  object,
  ref,
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
/** One work item per instance. The exact claim reference is its fencing token. */
export function workClaim({ minLeaseMs = 1000, maxLeaseMs = 600000 } = {}) {
  if (
    !Number.isSafeInteger(minLeaseMs) ||
    !Number.isSafeInteger(maxLeaseMs) ||
    minLeaseMs < 1 ||
    maxLeaseMs < minLeaseMs
  )
    throw Error("INVALID_LEASE_BOUNDS");
  const fields = {
      ttl_ms: { type: "integer", minimum: minLeaseMs, maximum: maxLeaseMs },
    },
    deadline = {
      from: "time_add",
      timestamp: time,
      milliseconds: body("ttl_ms"),
    };
  const claim = ref("claim_ref", "work.claim"),
    write = permission("WORKER", "CLAIM");
  const leaseReads = [
    "work_state",
    "lease_holder",
    "lease_expires",
    "lease_ref",
  ];
  const owns = [
    ...write,
    eq(state("work_state"), literal("OPEN")),
    eq(state("lease_holder"), actor),
    eq(body("claim_ref"), state("lease_ref")),
  ];
  const newLease = [
    append(
      "work.claim",
      { author: actor, expires_at: deadline },
      { slot: "claim" },
    ),
    set("lease_holder", actor),
    set("lease_expires", deadline),
    set("lease_ref", produced("claim")),
  ];
  const changes = ["lease_holder", "lease_expires", "lease_ref"];
  const grant = (id, guards, extraFields = {}) =>
    action(id, { ...fields, ...extraFields }, guards, newLease, {
      reads: leaseReads,
      writes: changes,
    });
  return {
    id: "work-claim",
    initial_state: {
      work_state: "OPEN",
      lease_holder: null,
      lease_expires: 0,
      lease_ref: null,
      result_ref: null,
    },
    roles: ["WORKER", "INTEGRATOR"],
    capabilities: ["CLAIM", "SUBMIT", "REOPEN"],
    schemas: {
      "work.claim": schema({ author: "string", expires_at: "integer" }),
      "work.result": schema({
        author: "string",
        claim_ref: "json",
        artifact_digest: "string",
      }),
    },
    actions: [
      grant("work.claim", [
        ...write,
        eq(state("work_state"), literal("OPEN")),
        eq(state("lease_holder"), literal(null)),
      ]),
      grant(
        "work.renew",
        [
          ...owns,
          { op: "lt", left: time, right: state("lease_expires") },
          { op: "gt", left: deadline, right: state("lease_expires") },
        ],
        { claim_ref: exact("work.claim") },
      ),
      grant("work.reclaim", [
        ...write,
        eq(state("work_state"), literal("OPEN")),
        not(eq(state("lease_holder"), literal(null))),
        { op: "gte", left: time, right: state("lease_expires") },
      ]),
      action(
        "work.release",
        { claim_ref: exact("work.claim") },
        owns,
        [
          set("lease_holder", literal(null)),
          set("lease_expires", literal(0)),
          set("lease_ref", literal(null)),
        ],
        { reads: leaseReads, writes: changes },
      ),
      action(
        "work.submit",
        {
          claim_ref: exact("work.claim"),
          artifact_digest: { type: "source_sha256" },
        },
        [
          ...permission("WORKER", "SUBMIT"),
          eq(state("work_state"), literal("OPEN")),
          eq(state("lease_holder"), actor),
          eq(body("claim_ref"), state("lease_ref")),
          { op: "lt", left: time, right: state("lease_expires") },
        ],
        [
          append(
            "work.result",
            {
              author: actor,
              claim_ref: claim,
              artifact_digest: body("artifact_digest"),
            },
            {
              slot: "result",
              relations: [{ kind: "consumes_claim", target: claim }],
            },
          ),
          set("result_ref", produced("result")),
          set("work_state", literal("SUBMITTED")),
          set("lease_holder", literal(null)),
          set("lease_ref", literal(null)),
          set("lease_expires", literal(0)),
        ],
        { reads: leaseReads, writes: ["result_ref", "work_state", ...changes] },
      ),
      action(
        "work.reopen",
        { result_ref: exact("work.result") },
        [
          ...permission("INTEGRATOR", "REOPEN"),
          {
            op: "in",
            value: state("work_state"),
            set: [literal("SUBMITTED"), literal("REVIEWED")],
          },
          eq(body("result_ref"), state("result_ref")),
        ],
        [set("work_state", literal("OPEN")), set("result_ref", literal(null))],
        {
          reads: ["work_state", "result_ref"],
          writes: ["work_state", "result_ref"],
        },
      ),
    ],
  };
}
