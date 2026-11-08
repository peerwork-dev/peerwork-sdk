// SPDX-License-Identifier: Apache-2.0
import { DatabaseSync } from "node:sqlite";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdirSync,
  lstatSync,
  chmodSync,
  realpathSync,
  openSync,
  closeSync,
  constants,
} from "node:fs";
import { dirname, resolve } from "node:path";
const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
/** One identity/service/workspace/instance/filter per store. Metadata only, no body plaintext. */
export class DeliveryStore {
  constructor(
    path,
    binding,
    { maxEvents = 1024, maxBytes = 8 * 1024 * 1024, now = Date.now } = {},
  ) {
    path = resolve(path);
    const dir = dirname(path);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (realpathSync(dir) !== dir || lstatSync(dir).mode & 0o077)
      throw Error("PRIVATE_STATE_DIRECTORY_REQUIRED");
    const fd = openSync(
      path,
      constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    closeSync(fd);
    if (lstatSync(path).mode & 0o077)
      throw Error("PRIVATE_STATE_FILE_REQUIRED");
    this.db = new DatabaseSync(path);
    this.db.exec(
      "PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA busy_timeout=3000;CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY,payload TEXT NOT NULL,hash TEXT NOT NULL,lease TEXT,until_ms INTEGER);CREATE TABLE IF NOT EXISTS decisions(k TEXT PRIMARY KEY,intent TEXT NOT NULL,result TEXT);",
    );
    this.now = now;
    this.maxEvents = maxEvents;
    this.maxBytes = maxBytes;
    this.binding = hash(binding);
    try {
      this.atomic(() => {
        const previous = this.get("binding");
        if (previous && previous !== this.binding)
          throw Error("CONSUMER_BINDING_CHANGED");
        if (!previous) this.put("binding", this.binding);
      });
    } catch (e) {
      this.db.close();
      throw e;
    }
  }
  atomic(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  get(k) {
    return this.db.prepare("SELECT v FROM meta WHERE k=?").get(k)?.v ?? null;
  }
  put(k, v) {
    this.db
      .prepare(
        "INSERT INTO meta VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
      )
      .run(k, v);
  }
  position() {
    const value = this.get("position");
    return value ? JSON.parse(value) : null;
  }
  ingest(events, next, { previous = this.position() } = {}) {
    if (
      !Number.isSafeInteger(next.after) ||
      next.after < 0 ||
      (next.cursor !== null && typeof next.cursor !== "string") ||
      events.length > 32
    )
      throw Error("INVALID_EVENT_PAGE");
    return this.atomic(() => {
      if (JSON.stringify(this.position()) !== JSON.stringify(previous))
        throw Error("CONSUMER_POSITION_CHANGED");
      const used = this.db
        .prepare(
          "SELECT count(*) n,coalesce(sum(length(CAST(payload AS BLOB))),0) bytes FROM events",
        )
        .get();
      if (
        Number(used.n) + events.length > this.maxEvents ||
        Number(used.bytes) + Buffer.byteLength(JSON.stringify(events)) >
          this.maxBytes
      )
        throw Error("CONSUMER_BACKPRESSURE");
      let last = -1;
      for (const e of events) {
        if (!Number.isSafeInteger(e.sequence) || e.sequence <= last)
          throw Error("INVALID_EVENT_SEQUENCE");
        last = e.sequence;
        const payload = JSON.stringify({
            sequence: e.sequence,
            instance_id: e.instance_id,
            kind: e.kind,
            record_id: e.record_id,
            actor_id: e.actor_id,
            created_at: e.created_at,
            summary: e.summary,
          }),
          digest = hash(payload),
          old = this.db
            .prepare("SELECT hash FROM events WHERE seq=?")
            .get(e.sequence);
        if (old && old.hash !== digest) throw Error("EVENT_IDENTITY_CONFLICT");
        this.db
          .prepare(
            "INSERT OR IGNORE INTO events(seq,payload,hash) VALUES(?,?,?)",
          )
          .run(e.sequence, payload, digest);
      }
      this.put("position", JSON.stringify(next));
    });
  }
  receive(leaseMs = 30000) {
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1 || leaseMs > 600000)
      throw Error("INVALID_DELIVERY_LEASE");
    return this.atomic(() => {
      const row = this.db
        .prepare("SELECT * FROM events ORDER BY seq LIMIT 1")
        .get();
      if (!row || (row.lease && row.until_ms > this.now())) return null;
      const token = randomUUID(),
        until = this.now() + leaseMs;
      this.db
        .prepare("UPDATE events SET lease=?,until_ms=? WHERE seq=?")
        .run(token, until, row.seq);
      return { event: JSON.parse(row.payload), token, until };
    });
  }
  ack(delivery) {
    const r = this.db
      .prepare("DELETE FROM events WHERE seq=? AND lease=? AND until_ms>?")
      .run(delivery.event.sequence, delivery.token, this.now());
    if (r.changes !== 1) throw Error("STALE_DELIVERY_LEASE");
  }
  saveDecision(key, intent) {
    if ("plaintext_contents" in intent)
      throw Error("USE_BODY_ARTIFACT_REFERENCE");
    return this.atomic(() => {
      const wire = JSON.stringify(intent),
        old = this.db
          .prepare("SELECT intent FROM decisions WHERE k=?")
          .get(key);
      if (old && old.intent !== wire) throw Error("DECISION_CHANGED");
      if (
        !old &&
        Number(this.db.prepare("SELECT count(*) n FROM decisions").get().n) >=
          1024
      )
        throw Error("DECISION_BACKPRESSURE");
      this.db
        .prepare("INSERT OR IGNORE INTO decisions(k,intent) VALUES(?,?)")
        .run(key, wire);
      return this.decision(key);
    });
  }
  decision(key) {
    const r = this.db.prepare("SELECT * FROM decisions WHERE k=?").get(key);
    return r
      ? {
          intent: JSON.parse(r.intent),
          result: r.result ? JSON.parse(r.result) : null,
        }
      : null;
  }
  result(key, value) {
    this.db
      .prepare("UPDATE decisions SET result=? WHERE k=?")
      .run(JSON.stringify(value), key);
  }
  close() {
    this.db.close();
  }
}
