// Opt-in synthetic-fixture diagnostics only. No SQL text, values, IDs or error
// messages leave the observer; timings include driver queue/IO, not just PG CPU.
import {AsyncLocalStorage} from 'node:async_hooks';

const TABLES = ['communication_deliveries','communication_mailboxes','communication_messages',
  'communication_grants','event_frontiers','workspace_capacity','accounting_entries',
  'commands','events','memberships','identities','workspaces'];
export function observeFixtureQueries(pool) {
  const active = new AsyncLocalStorage(), wrapped = new WeakSet();
  const mark = (type, sql) => {
    const scope = active.getStore();
    if (!scope || scope.closed) return () => {};
    const started = performance.now();
    scope[type + '_started']++;
    let done = false;
    return () => {
      if (done) return;
      done = true;
      if (scope.closed) return;
      const ended = performance.now();
      scope[type + '_completed']++;
      scope[type + '_await_sum_ms'] += ended - started;
      if (type === 'query') {
        if (scope.queries.length >= 128) {scope.truncated = true; return;}
        const verb = /^\s*(SELECT|INSERT|UPDATE|DELETE|BEGIN|COMMIT|ROLLBACK|SET)\b/i.exec(sql ?? '')?.[1]?.toUpperCase() ?? 'OTHER';
        const table = TABLES.find(name => new RegExp('\\b' + name + '\\b','i').test(sql ?? '')) ?? 'OTHER';
        scope.queries.push({verb, table, locking: /\bFOR\s+(?:UPDATE|SHARE)\b|\bpg_advisory/i.test(sql ?? ''),
          started_ms: started - scope.started, ended_ms: ended - scope.started, elapsed_ms: ended - started});
      }
    };
  };
  const wrap = client => {
    if (!client || wrapped.has(client)) return client;
    wrapped.add(client);
    const query = client.query;
    client.query = function(...args) {
      const finish = mark('query', typeof args[0] === 'string' ? args[0] : args[0]?.text);
      const last = args.length - 1;
      if (typeof args[last] === 'function') {
        const callback = args[last];
        args[last] = function(...values) {finish(); return callback.apply(this,values);};
      }
      try {
        const result = query.apply(this,args);
        return result?.then ? result.then(value => {finish(); return value;}, error => {finish(); throw error;}) : result;
      } catch (error) {finish(); throw error;}
    };
    return client;
  };
  const connect = pool.connect;
  pool.connect = function(...args) {
    const finish = mark('connection');
    if (typeof args[0] === 'function') {
      const callback = args[0];
      args[0] = function(error,client,release) {finish(); return callback.call(this,error,wrap(client),release);};
    }
    try {
      const result = connect.apply(this,args);
      return result?.then ? result.then(client => {finish(); return wrap(client);}, error => {finish(); throw error;}) : result;
    } catch (error) {finish(); throw error;}
  };
  return {
    async measure(body) {
      const scope = {started: performance.now(),closed: false,queries: [],truncated: false,
        query_started: 0,query_completed: 0,query_await_sum_ms: 0,
        connection_started: 0,connection_completed: 0,connection_await_sum_ms: 0};
      try {
        const value = await active.run(scope,body);
        const metrics = {query_started: scope.query_started,query_completed: scope.query_completed,
          incomplete_at_headers: scope.query_started - scope.query_completed,
          query_await_sum_ms: scope.query_await_sum_ms,
          connection_started: scope.connection_started,connection_completed: scope.connection_completed,
          incomplete_connections_at_headers: scope.connection_started - scope.connection_completed,
          connection_await_sum_ms: scope.connection_await_sum_ms,
          query_spans_truncated: scope.truncated,queries: scope.queries.map(item => ({...item}))};
        // Union distinguishes time awaiting at least one query from a sum of
        // overlapping/queued driver calls. Neither is pure backend execution.
        let union = 0, until = 0;
        for (const item of [...scope.queries].sort((a,b) => a.started_ms - b.started_ms)) {
          union += Math.max(0,item.ended_ms - Math.max(until,item.started_ms));
          until = Math.max(until,item.ended_ms);
        }
        metrics.completed_query_await_union_ms = union;
        return {value,metrics};
      } finally {scope.closed = true;}
    },
  };
}
