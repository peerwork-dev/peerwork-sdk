#!/bin/bash
set -euo pipefail
task_root="$1"
unshare --user --map-root-user --mount --pid --fork /bin/bash -euc '
  task_root="$1"
  for device in null zero urandom; do mount --bind "/dev/$device" "$task_root/dev/$device"; done
  chroot "$task_root" /usr/bin/env -i \
    PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/local/bin:/usr/bin:/bin \
    /bin/bash /work/sdk-pending-multipart/tests/install-installed-historical-pending-multipart-inner.sh
' install "$task_root"
