import {test} from 'node:test';
import assert from 'node:assert/strict';
import {delayFixtureResponse} from './fixture-latency.mjs';

test('zero delay preserves the exact response', async () => {
  const response = new Response('unchanged');
  assert.equal(await delayFixtureResponse(response, 0), response);
});

test('burst chunks and headers pay one overlapping delay, preserving bytes', async () => {
  const started = performance.now();
  const source = new ReadableStream({start(controller) {
    for (let i = 0; i < 8; i++) controller.enqueue(new Uint8Array([i]));
    controller.close();
  }});
  const response = await delayFixtureResponse(new Response(source, {status: 201, headers: {'x-fixture': 'kept'}}), 50);
  assert.equal(response.status, 201);
  assert.equal(response.headers.get('x-fixture'), 'kept');
  assert.deepEqual([...new Uint8Array(await response.arrayBuffer())], [0,1,2,3,4,5,6,7]);
  const elapsed = performance.now() - started;
  assert.ok(elapsed >= 45, `missing latency: ${elapsed}`);
  assert.ok(elapsed < 300, `serialized per-chunk latency: ${elapsed}`);
});

test('cancelling the downstream also cancels the original stream', async () => {
  let cancelled = false;
  const source = new ReadableStream({cancel() {cancelled = true;}});
  const response = await delayFixtureResponse(new Response(source), 10);
  await response.body.cancel();
  assert.equal(cancelled, true);
});

test('excess queued bytes fail explicitly instead of dropping eligible frames', async () => {
  const source = new ReadableStream({start(controller) {
    controller.enqueue(new Uint8Array(1024 * 1024 + 1));
    controller.close();
  }});
  const response = await delayFixtureResponse(new Response(source), 10);
  await assert.rejects(response.arrayBuffer(), /fixture link queue exceeded/);
});
