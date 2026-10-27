import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DeliveryStore } from "../../examples/research/shared/store.mjs";
import { EventHost } from "../../examples/research/shared/host.mjs";
import { WorkClient } from "../../examples/research/shared/client.mjs";
const event = (sequence) => ({
    sequence,
    kind: "action.accepted",
    instance_id: "instance",
    record_id: null,
    actor_id: "peer",
    created_at: 1,
    summary: {},
  }),
  binding = {
    origin: "https://service.example",
    actor_id: "alice",
    workspace_id: "w",
    instance_id: "i",
    filter_version: "1",
  };
function temp() {
  return mkdtempSync(join(tmpdir(), "peerwork-research-host-"));
}
test("atomic enqueue/checkpoint, restart, leases and bound identities prevent silent loss", () => {
  const dir = temp(),
    path = join(dir, "events.sqlite");
  let now = 100,
    store = new DeliveryStore(path, binding, { now: () => now });
  try {
    store.ingest([event(1), event(3)], { after: 3, cursor: null });
    assert.equal(store.position().after, 3);
    const first = store.receive(10);
    assert(first);
    store.close();
    store = new DeliveryStore(path, binding, { now: () => now });
    assert.equal(store.receive(), null);
    now = 110;
    assert.throws(() => store.ack(first), /STALE/);
    const again = store.receive();
    assert.equal(again.event.sequence, 1);
    store.ack(again);
    const second = store.receive();
    assert.equal(second.event.sequence, 3);
    store.ack(second);
    assert.equal(store.receive(), null);
    assert.throws(
      () => new DeliveryStore(path, { ...binding, actor_id: "bob" }),
      /BINDING_CHANGED/,
    );
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
test("backpressure leaves source position unchanged; invalid batches roll back", () => {
  const dir = temp(),
    store = new DeliveryStore(join(dir, "events.sqlite"), binding, {
      maxEvents: 1,
    });
  try {
    store.ingest([event(1)], { after: 1, cursor: null });
    assert.throws(
      () => store.ingest([event(2)], { after: 2, cursor: null }),
      /BACKPRESSURE/,
    );
    assert.equal(store.position().after, 1);
    const d = store.receive();
    store.ack(d);
    store.maxEvents = 3;
    assert.throws(
      () => store.ingest([event(3), event(2)], { after: 3, cursor: null }),
      /INVALID_EVENT_SEQUENCE/,
    );
    assert.equal(store.position().after, 1);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
test("polling resumes a bounded cursor chain and requires durable handoff before acknowledgment", async () => {
  const dir = temp(),
    store = new DeliveryStore(join(dir, "events.sqlite"), binding),
    calls = [],
    kernel = {
      executeStructureIntent: async (request) => {
        calls.push(request.body);
        return {
          state: "ACCEPTED",
          result: {
            structure:
              calls.length === 1
                ? { events: [event(7)], checkpoint: 7, next_cursor: "cursor" }
                : { events: [event(9)], checkpoint: 10, next_cursor: null },
          },
        };
      },
    };
  try {
    const host = new EventHost(kernel, store, { workspace_id: "w" });
    await host.poll({});
    await host.poll({});
    assert.deepEqual(calls, [{ limit: 32 }, { cursor: "cursor", limit: 32 }]);
    assert.equal(store.position().after, 10);
    await assert.rejects(
      host.dispatch(async () => ({})),
      /DURABLE_HANDOFF/,
    );
    assert.equal(store.db.prepare("SELECT count(*) n FROM events").get().n, 2);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
test("unknown submission resumes its original command; no plaintext body is stored in host SQL", async () => {
  const dir = temp(),
    store = new DeliveryStore(join(dir, "events.sqlite"), binding),
    calls = [];
  let submits = 0;
  const kernel = {
    actor_id: "alice",
    executeStructureIntent: async (request) => {
      calls.push(request);
      submits++;
      return {
        state: "PENDING",
        command_id: "original",
        retryable: true,
        effect_certainty: "UNKNOWN",
      };
    },
    resumeStructureIntent: async (id) => {
      assert.equal(id, "original");
      return {
        state: "ACCEPTED",
        result: {
          command_id: id,
          structure: {
            revision: 2,
            produced_record_ids: ["record"],
            state: { work_state: "SUBMITTED" },
          },
        },
      };
    },
  };
  try {
    const body = join(dir, "result.body");
    writeFileSync(body, "private result text", { mode: 0o600 });
    const { digest } = await import(
      "../../examples/research/shared/client.mjs"
    );
    const client = new WorkClient(
        kernel,
        { workspace_id: "w", instance_id: "i", protocol_digest: "d" },
        store,
      ),
      args = {
        revision: 1,
        artifact: { path: body, sha256: digest(readFileSync(body)) },
      };
    const p = await client.act("work.submit", {}, "stable", args);
    assert.equal(p.effect_certainty, "UNKNOWN");
    const r = await client.act("work.submit", {}, "stable", args);
    assert.equal(r.state, "ACCEPTED");
    assert.equal(submits, 1);
    assert(
      !JSON.stringify(
        store.db.prepare("SELECT * FROM decisions").all(),
      ).includes("private result text"),
    );
    await assert.rejects(
      client.act("work.submit", { changed: true }, "stable", args),
      /DECISION_CHANGED/,
    );
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
