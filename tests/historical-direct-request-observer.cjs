// Operator-only bounded request hashes. Preserve the fixture's original
// server/request/origin behavior; never persist a request body or private key.
const http = require('node:http');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { syncBuiltinESMExports } = require('node:module');
const output = process.env.PEERWORK_TEST_REQUEST_OBSERVER;
if (!output) throw new Error('request observer needs an explicit operator path');
const original = http.createServer;
http.createServer = function (...args) {
  const index = args.findIndex(value => typeof value === 'function');
  if (index >= 0) {
    const listener = args[index];
    args[index] = function (request, response) {
      if (request.method === 'POST' && /^\/api\/workspace\/v1\/secure\/workspaces\/[A-Za-z0-9_-]+\/commits$/.test(request.url)) {
        const chunks = [];
        let bytes = 0;
        request.on('data', chunk => {
          bytes += chunk.length;
          if (bytes <= 8 * 1024 * 1024) chunks.push(chunk);
        });
        request.on('end', () => {
          if (bytes > 8 * 1024 * 1024) throw new Error('observer request cap');
          const body = Buffer.concat(chunks);
          const value = JSON.parse(body.toString('utf8'));
          const commandId = value?.commit?.payload?.command_id;
          if (typeof commandId !== 'string') throw new Error('observer commit ID');
          fs.appendFileSync(output, JSON.stringify({ method: request.method,
            path: request.url, host: request.headers.host, command_id: commandId,
            body_bytes: body.length, body_sha256: crypto.createHash('sha256').update(body).digest('hex'),
          }) + '\n', { mode: 0o600 });
        });
      }
      return listener.call(this, request, response);
    };
  }
  return original.apply(this, args);
};
syncBuiltinESMExports();
