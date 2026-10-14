#!/bin/bash
set -euo pipefail
task_root="$1"
unshare --user --map-root-user --mount --pid --fork /bin/bash -euc '
  task_root="$1"
  for device in null zero urandom; do mount --bind "/dev/$device" "$task_root/dev/$device"; done
  chroot "$task_root" /usr/bin/env -i \
    PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/work/sdk-historical-direct/dist/python-consumer \
    PEERWORK_TEST_SDK_ROOT=/work/sdk-historical-direct \
    PEERWORK_TEST_STATE=/work/sdk-historical-direct/dist/historical-direct-state-split \
    PEERWORK_TEST_HOST_FIXTURE_JSON=/work/sdk-historical-direct/dist/historical-direct-state-split/host-fixture.json \
    PEERWORK_TEST_LEGACY_ROOT=/legacy-checked-on-host \
    PEERWORK_TEST_LEGACY_COMMIT=f828b6c50a0a58d1e718af90f653b214adcc3328 \
    PEERWORK_TEST_NODE=/opt/node24/bin/node \
    PEERWORK_TEST_NODE_PACKAGE=/work/sdk-historical-direct/dist/node-consumer/node_modules/@peerwork/agent-sdk \
    PEERWORK_TEST_CLI=/work/sdk-historical-direct/target/release/peerwork \
    PEERWORK_TEST_ATTACH_SOURCE_SHA256=a12c2e4b7df075970e800082f67acc4762530c322a041c1739ee2dd231b32a95 \
    PEERWORK_TEST_LEGACY_HELPER_SHA256=d4c20a4d02a76e2f8e468f3aa2e65c0b6185502915b26f3b698ebba7c47b4500 \
    PEERWORK_TEST_REFERENCE_FIXTURE_SHA256=50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0 \
    /bin/bash -euc '\''
      getconf GNU_LIBC_VERSION
      /work/sdk-historical-direct/target/release/peerwork version
      cd /work/sdk-historical-direct
      /opt/python/cp311-cp311/bin/python tests/installed-historical-direct-packets-completed-smoke.py
    '\''
' consumer "$task_root"
