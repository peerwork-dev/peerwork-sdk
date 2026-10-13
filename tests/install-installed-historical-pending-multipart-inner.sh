#!/bin/bash
set -euo pipefail
cd /work/sdk-pending-multipart
mkdir -p dist/npm dist/node-consumer dist/python-consumer
/opt/node24/bin/node bindings/node/scripts/package-platform.mjs linux-x64-gnu target/release/libpeerwork_node_native.so dist/npm
/opt/node24/bin/npm pack ./bindings/node --pack-destination dist/npm --offline --ignore-scripts
/opt/node24/bin/npm pack ./dist/npm/agent-sdk-linux-x64-gnu --pack-destination dist/npm --offline --ignore-scripts
printf '%s\n' '{"name":"peerwork-offline-consumer","private":true}' > dist/node-consumer/package.json
/opt/node24/bin/npm install --prefix dist/node-consumer --offline --ignore-scripts --no-audit --no-fund --no-save ./dist/npm/peerwork-agent-sdk-0.0.1.tgz ./dist/npm/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz
/opt/python/cp311-cp311/bin/python -m pip install --no-index --no-deps --target dist/python-consumer dist/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl
PYTHONPATH=/work/sdk-pending-multipart/dist/python-consumer /opt/python/cp311-cp311/bin/python -c 'import peerwork; print(peerwork.__file__)'
/opt/node24/bin/node -e 'const p=require("/work/sdk-pending-multipart/dist/node-consumer/node_modules/@peerwork/agent-sdk"); console.log(typeof p.openSecureOwnerWorkspaces)'
/work/sdk-pending-multipart/target/release/peerwork --help >/dev/null
