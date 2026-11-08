// SPDX-License-Identifier: Apache-2.0
import {
  cooperationProtocol,
  composeProtocol,
  sharedFindings,
} from "../../meta-protocols/index.mjs";
import { Scenario, token } from "./scenario.mjs";
import { advanceWorker, sha } from "./flow.mjs";
export async function runOffline(recipe) {
  if (!["delm", "agensh"].includes(recipe)) throw Error("RECIPE_UNKNOWN");
  const boardState = new Scenario(composeProtocol([sharedFindings()])),
    states = [0, 1].map(
      (i) =>
        new Scenario(cooperationProtocol(), {
          seed: "work-" + i,
          now: Date.now(),
        }),
    ),
    bodies = new Map(),
    notes = [],
    merged = new Map();
  const clients = (actor) => {
    const make = (scenario) => ({
      read: async () => ({
        state: structuredClone(scenario.state),
        revision: scenario.revision,
      }),
      record: async (r) => ({
        structure: { structure: scenario.records.get(r.record_id).structure },
        opened_contents: [
          {
            record_id: r.record_id,
            state: "OPENED",
            text: bodies.get(r.record_id),
          },
        ],
      }),
      act: async (
        action,
        body,
        key,
        { refs = [], revision, artifact } = {},
      ) => {
        try {
          const r = scenario.execute(actor, action, body, refs, { revision });
          if (artifact)
            for (const id of r.produced_record_ids)
              bodies.set(id, artifact.text);
          if (action === "finding.publish")
            notes.push({ actor, text: artifact.text });
          return {
            state: "ACCEPTED",
            revision: r.revision,
            state_snapshot: r.state,
          };
        } catch (e) {
          return { state: "REJECTED", code: e.code ?? e.message };
        }
      },
    });
    return { board: make(boardState), work: states.map(make) };
  };
  const run = async (label) => {
    const actor = token(label),
      cache = new Map(),
      c = clients(actor);
    for (let i = 0; i < 20; i++) {
      const r = await advanceWorker({
        recipe,
        actor,
        ...c,
        artifact: async (key, value) => {
          if (!cache.has(key)) {
            const text = typeof value === "function" ? await value() : value;
            cache.set(key, { text, sha256: sha(text) });
          }
          return cache.get(key);
        },
        findings: async () => notes.filter((n) => n.actor !== actor),
        integrate: async ({ task, text }) => {
          if (recipe === "agensh") merged.set(task.id, text);
        },
      });
      if (r.done) return r;
      await new Promise((resolve) => setImmediate(resolve));
    }
    throw Error("OFFLINE_PROGRESS_STALLED");
  };
  const peers = await Promise.all(["alice", "bob"].map(run));
  if (peers.some((p) => p.candidate.total !== 17))
    throw Error("OFFLINE_CANDIDATE_INVALID");
  return {
    status: "PASS",
    recipe,
    simulated: true,
    authoritative: false,
    worker_count: 2,
    candidate_count: peers.length,
    total: 17,
    shared_findings: notes.length,
    adopted_work_items: states.filter((s) => s.state.work_state === "DONE")
      .length,
    shared_artifacts: recipe === "agensh" ? merged.size : null,
    model_quality_measured: false,
  };
}
