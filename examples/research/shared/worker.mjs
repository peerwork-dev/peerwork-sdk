#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  renameSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { loadSDK } from "./sdk.mjs";
import { DeliveryStore } from "./store.mjs";
import { WorkClient, accepted, digest } from "./client.mjs";
import { EventHost } from "./host.mjs";
import { advanceWorker, scriptedArtifact } from "./flow.mjs";
import { runAgentCommand } from "./agent-command.mjs";
import { gitIntegrator } from "./git.mjs";
const cfg = JSON.parse(readFileSync(process.argv[2], "utf8")),
  recipe = process.argv[3];
if (!["agensh", "delm"].includes(recipe)) throw Error("RECIPE_UNKNOWN");
const sdk = loadSDK(),
  kernel = await sdk.openKernel({
    origin: cfg.origin,
    identityPath: cfg.identityPath,
    journalPath: cfg.journalPath,
    authority: cfg.authority ?? undefined,
    allowLoopbackHttp: cfg.allowLoopbackHttp,
  });
if (kernel.actor_id !== cfg.actor_id) throw Error("WORKER_IDENTITY_MISMATCH");
const dir = join(cfg.stateDir, recipe);
mkdirSync(dir, { recursive: true, mode: 0o700 });
const store = new DeliveryStore(join(dir, "events.sqlite"), {
    origin: cfg.origin,
    authority: cfg.authority,
    actor_id: cfg.actor_id,
    workspace_id: cfg.workspace_id,
    board: cfg.board,
    work: cfg.work,
    recipe,
    filter_version: "1",
  }),
  scope = (x) => ({ workspace_id: cfg.workspace_id, ...x }),
  board = new WorkClient(kernel, scope(cfg.board), store),
  work = cfg.work.map((x) => new WorkClient(kernel, scope(x), store)),
  host = new EventHost(kernel, store, { workspace_id: cfg.workspace_id });
const controller = new AbortController(),
  timer = setTimeout(() => controller.abort(), cfg.timeoutMs),
  signal = controller.signal;
const artifact = async (key, value) => {
  const path = join(dir, digest(key) + ".body");
  if (!existsSync(path)) {
    const text = typeof value === "function" ? await value() : value;
    const tmp = path + ".tmp";
    writeFileSync(tmp, text, { mode: 0o600 });
    renameSync(tmp, path);
  }
  const bytes = readFileSync(path);
  return { path, sha256: digest(bytes) };
};
const integrate =
  recipe === "agensh"
    ? await gitIntegrator(dir, cfg.bareRepository, cfg.actor_id)
    : async () => {};
let polls = 0,
  deliveries = 0,
  findingsRead = 0,
  qualityMode = cfg.agentCommand
    ? "external_harness"
    : "scripted_protocol_fixture";
try {
  while (!signal.aborted) {
    // Reconcile durable work before choosing any replacement operation.
    const pending = store.db
      .prepare(
        "SELECT k,result FROM decisions WHERE result IS NULL OR json_extract(result,'$.state')='PENDING' LIMIT 8",
      )
      .all();
    let blocked = false;
    for (const row of pending) {
      const prior = row.result ? JSON.parse(row.result) : null;
      if (prior?.retryable === false) {
        blocked = true;
        break;
      }
      const r = await board.resume(row.k);
      if (r.state === "PENDING") blocked = true;
    }
    if (blocked) {
      await delay(1500, undefined, { signal });
      continue;
    }
    const eventCount = await host.poll({ signal });
    polls++;
    while (await host.dispatch(async () => "ignored")) deliveries++;
    const findings = async () => {
      const r = accepted(
        await kernel.executeStructureIntent(
          {
            action: "structure.records.read",
            ...scope(cfg.board),
            body: { schema: "finding", limit: 16 },
          },
          { signal },
        ),
      );
      if (r.structure.next_cursor) throw Error("DEMO_FINDINGS_BUDGET_EXCEEDED");
      findingsRead++;
      return r.structure.records
        .filter(
          (x) =>
            x.structure.author !== cfg.actor_id &&
            x.structure.status === "ACTIVE",
        )
        .map((row) => ({
          record_id: row.record_id,
          revision: row.revision,
          kind: row.structure.kind,
          text:
            r.opened_contents.find(
              (x) => x.record_id === row.record_id && x.state === "OPENED",
            )?.text ?? null,
        }));
    };
    const r = await advanceWorker({
      recipe,
      actor: cfg.actor_id,
      board,
      work,
      artifact,
      integrate,
      findings,
      agent: cfg.agentCommand
        ? async (input) =>
            (
              await runAgentCommand(
                cfg.agentCommand,
                {
                  ...input,
                  goal: "Return JSON text {task_id,value}; value is the sum of task.numbers. Use peer findings when applicable.",
                },
                { signal, timeoutMs: cfg.agentTimeoutMs, cwd: dir },
              )
            ).text
        : async ({ task }) => scriptedArtifact(task),
    });
    if (r.done) {
      writeFileSync(
        join(dir, "candidate.json"),
        JSON.stringify(r.candidate, null, 2) + "\n",
        { mode: 0o600 },
      );
      console.log(
        JSON.stringify({
          status: "PASS",
          actor_id: cfg.actor_id,
          recipe,
          mode: qualityMode,
          candidate_total: r.candidate.total,
          polls,
          delivered_events: deliveries,
          findings_reads: findingsRead,
        }),
      );
      break;
    }
    // Fast initial progress, bounded steady polling; no Agent-authored listening loops.
    await delay(eventCount ? 500 : 2000, undefined, { signal });
  }
  if (signal.aborted) throw Error("DEMO_DEADLINE_REACHED_RESUME_SAME_BINDING");
} catch (error) {
  console.log(
    JSON.stringify({
      status: "PENDING_OR_FAILED",
      code: error.code ?? error.message,
      recipe,
      actor_id: cfg.actor_id,
      recovery: "RERUN_SAME_BINDING",
    }),
  );
  process.exitCode = 2;
} finally {
  clearTimeout(timer);
  store.close();
}
