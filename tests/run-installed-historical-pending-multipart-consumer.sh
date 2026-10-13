#!/bin/bash
set -euo pipefail
task_root="$1"
unshare --user --map-root-user --mount --pid --fork /bin/bash -euc '
  task_root="$1"
  for device in null zero urandom; do mount --bind "/dev/$device" "$task_root/dev/$device"; done
  chroot "$task_root" /usr/bin/env -i \
    PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/work/sdk-pending-multipart/dist/python-consumer \
    PEERWORK_TEST_SDK_ROOT=/work/sdk-pending-multipart \
    PEERWORK_TEST_STATE=/work/sdk-pending-multipart/dist/pending-multipart-state-split \
    PEERWORK_TEST_HOST_FIXTURE_JSON=/work/sdk-pending-multipart/dist/pending-multipart-state-split/host-fixture.json \
    PEERWORK_TEST_LEGACY_ROOT=/legacy-checked-on-host \
    PEERWORK_TEST_LEGACY_COMMIT=f828b6c50a0a58d1e718af90f653b214adcc3328 \
    PEERWORK_TEST_NODE=/opt/node24/bin/node \
    PEERWORK_TEST_NODE_PACKAGE=/work/sdk-pending-multipart/dist/node-consumer/node_modules/@peerwork/agent-sdk \
    PEERWORK_TEST_CLI=/work/sdk-pending-multipart/target/release/peerwork \
    PEERWORK_TEST_ATTACH_SOURCE_SHA256=c20deaf965105502a973a5a72f492ad0a42158798069febe756473d0bf3135d1 \
    PEERWORK_TEST_LEGACY_HELPER_SHA256=e4022d765221dd00f28fde945ea8f0f73b3f52042181a8573cb83e26475b0fd6 \
    PEERWORK_TEST_REFERENCE_FIXTURE_SHA256=50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0 \
    /bin/bash -euc '\''
      getconf GNU_LIBC_VERSION
      /work/sdk-pending-multipart/target/release/peerwork version
      cd /work/sdk-pending-multipart
      /opt/python/cp311-cp311/bin/python tests/installed-historical-pending-multipart-stage-smoke.py
    '\''
' consumer "$task_root"
