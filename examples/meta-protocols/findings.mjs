// SPDX-License-Identifier: Apache-2.0
import {
  literal,
  body,
  actor,
  ref,
  payload,
  eq,
  not,
  permission,
  schema,
  exact,
  append,
  action,
} from "./dsl.mjs";
/** DeLM/Agensh-inspired findings, with explicit authorship and versioned correction. */
export function sharedFindings() {
  const kinds = ["OBSERVED", "FACT", "FAIL", "PATCH_SUMMARY"];
  const previous = ref("previous", "finding");
  const write = permission("WORKER", "FINDING"),
    fields = {
      kind: { type: "enum", values: kinds },
      subject: { type: "string", maxBytes: 120 },
    };
  const revision = (status, kind) =>
    append(
      "finding",
      {
        author: actor,
        kind,
        subject: payload(previous, "subject"),
        status: literal(status),
        previous,
      },
      {
        entity: { mode: "revise", slot: "finding", parent: previous },
        relations: [{ kind: "supersedes", target: previous }],
      },
    );
  return {
    id: "shared-findings",
    initial_state: {},
    roles: ["WORKER"],
    capabilities: ["FINDING"],
    schemas: {
      finding: schema({
        author: "string",
        kind: "string",
        subject: "string",
        status: "string",
        previous: "json",
      }),
      "finding.challenge": schema({ author: "string", target: "json" }),
    },
    actions: [
      action(
        "finding.publish",
        fields,
        write,
        [
          append(
            "finding",
            {
              author: actor,
              kind: body("kind"),
              subject: body("subject"),
              status: literal("ACTIVE"),
              previous: literal(null),
            },
            { entity: { mode: "new", slot: "finding" } },
          ),
        ],
        { entities: ["finding"] },
      ),
      action(
        "finding.correct",
        { previous: exact("finding"), kind: fields.kind },
        [
          ...write,
          eq(payload(previous, "author"), actor),
          eq(payload(previous, "status"), literal("ACTIVE")),
        ],
        [revision("ACTIVE", body("kind"))],
        { entities: ["finding"] },
      ),
      action(
        "finding.retract",
        { previous: exact("finding") },
        [
          ...write,
          eq(payload(previous, "author"), actor),
          eq(payload(previous, "status"), literal("ACTIVE")),
        ],
        [revision("RETRACTED", payload(previous, "kind"))],
        { entities: ["finding"] },
      ),
      action(
        "finding.challenge",
        { previous: exact("finding") },
        [...write, not(eq(payload(previous, "author"), actor))],
        [
          append(
            "finding.challenge",
            { author: actor, target: previous },
            { relations: [{ kind: "challenges", target: previous }] },
          ),
        ],
      ),
    ],
  };
}
