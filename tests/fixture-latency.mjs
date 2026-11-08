// Maintainer-only link simulation, not production transport. Delays overlap:
// a burst must not acquire another one-way latency for each subsequent chunk.
import {setTimeout as pause} from 'node:timers/promises';

// Opt-in proof runs need a real lower bound, not a timer's rounded deadline.
export async function minimumFixtureDelay(delayMs, {clock = () => performance.now(), sleep = pause} = {}) {
  if (!Number.isFinite(delayMs) || delayMs < 0) throw RangeError('invalid fixture delay');
  const deadline = clock() + delayMs;
  for (;;) {
    const remaining = deadline - clock();
    if (remaining <= 0) return;
    await sleep(remaining);
  }
}

export async function delayFixtureResponse(response, delayMs) {
  if (!delayMs) return response;
  const reader = response.body?.getReader();
  const timers = new Set();
  let cancelled = false, queuedBytes = 0;
  const cancel = () => {
    cancelled = true;
    for (const timer of timers) clearTimeout(timer);
    timers.clear();
    void reader?.cancel().catch(() => {});
  };
  const body = reader ? new ReadableStream({
    start(controller) {
      const later = callback => {
        const timer = setTimeout(() => {
          timers.delete(timer);
          if (!cancelled) callback();
        }, delayMs);
        timers.add(timer);
      };
      void (async () => {
        try {
          for (;;) {
            const {done, value} = await reader.read();
            if (cancelled) return;
            if (done) { later(() => controller.close()); return; }
            queuedBytes += value.byteLength;
            if (queuedBytes > 1024 * 1024) throw Error('fixture link queue exceeded one MiB');
            later(() => { queuedBytes -= value.byteLength; controller.enqueue(value); });
          }
        } catch (error) {
          if (!cancelled) { cancel(); controller.error(error); }
        }
      })();
    },
    cancel,
  }) : null;
  // Start delaying chunks before holding headers, so initial data is not
  // charged twice. Signed SSE frames retain byte order and their original IDs.
  await pause(delayMs);
  return new Response(body, {status: response.status, statusText: response.statusText, headers: response.headers});
}
