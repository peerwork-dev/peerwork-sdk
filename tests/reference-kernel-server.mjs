// Development-only bridge to the pinned tracked Peerwork TypeScript kernel.
// PEERWORK_REFERENCE_ROOT names a built checkout; PEERWORK_TEST_STATE is a
// fresh private test directory. This script is never part of an SDK package.
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join} from 'node:path';
import {createServer} from 'node:http';

const root = process.env.PEERWORK_REFERENCE_ROOT;
const state = process.env.PEERWORK_TEST_STATE;
if (!root || !state) throw new Error('reference root and fresh state are required');
const requireFromReference = createRequire(join(root, 'package.json'));
const {serve} = await import(pathToFileURL(requireFromReference.resolve('@hono/node-server')).href);
const {openKernel, WorkspaceKernel} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-kernel.js')).href);
const {createWorkspaceControlApp} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-http.js')).href);
const db = openKernel(join(state, 'control.sqlite'), 'reference-kernel');
const kernel = new WorkspaceKernel(db, 'reference-kernel', Buffer.alloc(32, 71));
const real = serve({fetch: createWorkspaceControlApp(kernel).fetch, hostname: '127.0.0.1', port: 0});
await new Promise(resolve => real.once('listening', resolve));
const realOrigin = `http://127.0.0.1:${real.address().port}`;
let dropFirstPost = true;
const proxy = createServer(async (request, response) => {
  try {
    if (request.url === '/__test/counts') {
      const counts = {
        commands: db.prepare('SELECT count(*) n FROM commands').get().n,
        workspaces: db.prepare('SELECT count(*) n FROM workspaces').get().n,
      };
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify(counts));
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const original = await fetch(realOrigin + request.url, {
      method: request.method,
      headers: {'content-type': request.headers['content-type'] || 'application/json'},
      body: request.method === 'GET' ? undefined : Buffer.concat(chunks),
    });
    const bytes = Buffer.from(await original.arrayBuffer());
    if (request.method === 'POST' && dropFirstPost) {
      dropFirstPost = false;
      response.destroy(); // Real kernel has already committed and replied.
      return;
    }
    response.writeHead(original.status, {'content-type': original.headers.get('content-type') || 'application/json'});
    response.end(bytes);
  } catch (error) {
    if (!response.destroyed) { response.writeHead(500); response.end(); }
    process.stderr.write(`reference proxy error: ${error?.message || error}\n`);
  }
});
await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
process.stdout.write(JSON.stringify({origin: `http://127.0.0.1:${proxy.address().port}/`}) + '\n');
const shutdown = () => {
  proxy.closeAllConnections();
  proxy.close();
  real.closeAllConnections?.();
  real.close();
  db.close();
};
process.stdin.on('end', shutdown);
