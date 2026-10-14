#!/bin/bash
set -euo pipefail
task_root="$1"
unshare --user --map-root-user --mount --pid --fork /bin/bash -euc '
  task_root="$1"
  for device in null zero urandom; do mount --bind "/dev/$device" "$task_root/dev/$device"; done
  chroot "$task_root" /usr/bin/env -i \
    PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/work/sdk-multipart-orphan/dist/python-consumer \
    PEERWORK_TEST_SDK_ROOT=/work/sdk-multipart-orphan \
    PEERWORK_TEST_STATE=/work/sdk-multipart-orphan/dist/multipart-orphan-state-split \
    PEERWORK_TEST_HOST_FIXTURE_JSON=/work/sdk-multipart-orphan/dist/multipart-orphan-state-split/host-fixture.json \
    PEERWORK_TEST_LEGACY_ROOT=/legacy-checked-on-host \
    PEERWORK_TEST_LEGACY_COMMIT=f828b6c50a0a58d1e718af90f653b214adcc3328 \
    PEERWORK_TEST_NODE=/opt/node24/bin/node \
    PEERWORK_TEST_NODE_PACKAGE=/work/sdk-multipart-orphan/dist/node-consumer/node_modules/@peerwork/agent-sdk \
    PEERWORK_TEST_CLI=/work/sdk-multipart-orphan/target/release/peerwork \
    PEERWORK_TEST_ATTACH_SOURCE_SHA256=47d341987c34f21a533ecee8d255d8dd70bc3ffdc3388f72fd41bcdcf3c5f451 \
    PEERWORK_TEST_LEGACY_HELPER_SHA256=4da377dc9bb8831a38d48eb6c0ffb8e9a6263b99e226d2d41b7b57344961232a \
    PEERWORK_TEST_REFERENCE_FIXTURE_SHA256=50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0 \
    /bin/bash -euc '\''
      getconf GNU_LIBC_VERSION
      /work/sdk-multipart-orphan/target/release/peerwork version
      cd /work/sdk-multipart-orphan
      /opt/python/cp311-cp311/bin/python tests/installed-historical-multipart-orphan-stage-smoke.py
    '\''
' consumer "$task_root"
