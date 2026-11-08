import {test} from 'node:test';
import assert from 'node:assert/strict';
import {setTimeout as pause} from 'node:timers/promises';
import {observeFixtureQueries} from './fixture-query-metrics.mjs';

function fixture(failure) {
  const client = {query(...args) {
    const callback = args.at(-1);
    const result = pause(1).then(() => {if(failure)throw failure;return {rows: []};});
    if (typeof callback === 'function') {void result.then(value => callback(null,value),error => callback(error)); return;}
    return result;
  }};
  const pool = {connect(callback) {
    if (callback) {queueMicrotask(() => callback(null,client,() => {})); return;}
    return Promise.resolve(client);
  }};
  return {pool,observer: observeFixtureQueries(pool)};
}

test('interleaved request scopes share clients without exporting SQL or values', async () => {
  const {pool,observer} = fixture();
  const [a,b] = await Promise.all(['commands','workspaces'].map(table => observer.measure(async () => {
    const client = await pool.connect();
    await client.query(`SELECT 'secret-sql-literal' FROM ${table} WHERE id=$1`,['secret-bound-value']);
  })));
  assert.equal(a.metrics.queries[0].table,'commands');
  assert.equal(b.metrics.queries[0].table,'workspaces');
  assert.equal(a.metrics.query_completed,1);
  assert.equal(b.metrics.query_completed,1);
  assert.ok(!JSON.stringify([a.metrics,b.metrics]).includes('secret'));
});

test('callback connection/query API retains result completion', async () => {
  const {pool,observer} = fixture();
  const {metrics} = await observer.measure(() => new Promise((resolve,reject) => {
    pool.connect((error,client) => {
      if (error) return reject(error);
      client.query('UPDATE communication_mailboxes SET value=$1',[9],(error,result) => error ? reject(error) : resolve(result));
    });
  }));
  assert.equal(metrics.connection_started,1);
  assert.equal(metrics.query_completed,1);
  assert.equal(metrics.queries[0].verb,'UPDATE');
});

test('driver failures retain their original identity in Promise and callback APIs', async () => {
  const failure = new Error('synthetic driver failure'),{pool,observer} = fixture(failure);
  await assert.rejects(observer.measure(async () => {
    const client = await pool.connect();await client.query('SELECT * FROM commands');
  }),error => error === failure);
  await assert.rejects(observer.measure(() => new Promise((resolve,reject) => {
    pool.connect((error,client) => client.query('SELECT * FROM commands',(error,result) => error ? reject(error) : resolve(result)));
  })),error => error === failure);
});

test('late stream work cannot mutate a completed response-header observation', async () => {
  const {pool,observer} = fixture();let late;
  const {metrics} = await observer.measure(async () => {
    const client = await pool.connect();late = client.query('SELECT * FROM events');
  });
  const frozen = JSON.stringify(metrics);
  assert.equal(metrics.incomplete_at_headers,1);
  await late;
  assert.equal(JSON.stringify(metrics),frozen);
});

test('span storage is bounded and overlapping query times remain explicit', async () => {
  const {pool,observer} = fixture();
  const {metrics} = await observer.measure(async () => {
    const client = await pool.connect();
    await Promise.all(Array.from({length:130},() => client.query('SELECT * FROM commands FOR UPDATE')));
  });
  assert.equal(metrics.query_completed,130);
  assert.equal(metrics.queries.length,128);
  assert.equal(metrics.query_spans_truncated,true);
  assert.ok(metrics.completed_query_await_union_ms <= metrics.query_await_sum_ms);
  assert.ok(metrics.queries.every(item => item.locking));
});
