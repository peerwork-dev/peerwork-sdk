// SPDX-License-Identifier: Apache-2.0
import { setTimeout as delay } from "node:timers/promises";
import { accepted } from "./client.mjs";
/** Durable bounded polling over verified current Backend pages; no history replay. */
export class EventHost {
  constructor(client, store, scope) {
    this.client = client;
    this.store = store;
    this.scope = scope;
  }
  async poll({ signal } = {}) {
    const previous = this.store.position(),
      body = previous?.cursor
        ? { cursor: previous.cursor, limit: 32 }
        : previous
          ? { after_sequence: previous.after, limit: 32 }
          : { limit: 32 };
    const out = await this.client.executeStructureIntent(
        { action: "structure.events.read", ...this.scope, body },
        { signal },
      ),
      page = accepted(out).structure;
    this.store.ingest(
      page.events,
      { after: page.checkpoint, cursor: page.next_cursor ?? null },
      { previous },
    );
    return page.events.length;
  }
  async dispatch(handler, { leaseMs = 30000 } = {}) {
    const delivery = this.store.receive(leaseMs);
    if (!delivery) return false;
    const disposition = await handler(delivery.event);
    if (
      disposition !== "ignored" &&
      !(
        disposition?.decisionKey && this.store.decision(disposition.decisionKey)
      )
    )
      throw Error("DURABLE_HANDOFF_REQUIRED");
    this.store.ack(delivery);
    return true;
  }
  async run(
    handler,
    { signal, pollMs = 1000, maxBackoffMs = 30000, onError = () => {} } = {},
  ) {
    let backoff = pollMs;
    while (!signal?.aborted) {
      try {
        while (await this.dispatch(handler)) {}
        await this.poll({ signal });
        while (await this.dispatch(handler)) {}
        backoff = pollMs;
        await delay(pollMs, undefined, { signal });
      } catch (error) {
        if (signal?.aborted) break;
        const code = error.code ?? error.message;
        if (
          ![
            "SECURE_HTTP_502",
            "SECURE_HTTP_503",
            "SECURE_HTTP_504",
            "SECURE_HTTP_429",
            "SECURE_HTTP_TIMEOUT",
            "SECURE_HTTP_REQUEST",
            "SECURE_HTTP_TRANSPORT",
            "STALE_DELIVERY_LEASE",
          ].includes(code)
        )
          throw error;
        onError({ code, waiting_ms: backoff });
        try {
          await delay(backoff, undefined, { signal });
        } catch (e) {
          if (signal?.aborted) break;
          throw e;
        }
        backoff = Math.min(maxBackoffMs, backoff * 2);
      }
    }
  }
}
