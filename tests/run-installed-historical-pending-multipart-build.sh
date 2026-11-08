#!/bin/bash
set -euo pipefail
task_root="$1"
unshare --user --map-root-user --mount --pid --fork /bin/bash -euc '
  task_root="$1"
  for device in null zero urandom; do mount --bind "/dev/$device" "$task_root/dev/$device"; done
  chroot "$task_root" /usr/bin/env -i \
    PATH=/opt/rust/bin:/opt/rh/gcc-toolset-14/root/usr/bin:/opt/python/cp311-cp311/bin:/opt/node24/bin:/work/tools/bin:/usr/bin:/bin \
    LD_LIBRARY_PATH=/opt/rust/lib:/opt/rh/gcc-toolset-14/root/usr/lib64:/opt/rh/gcc-toolset-14/root/usr/lib \
    CARGO_HOME=/root/.cargo CARGO_TARGET_DIR=/work/sdk-pending-multipart/target CARGO_NET_OFFLINE=true \
    RUSTC=/opt/rust/bin/rustc RUSTDOC=/opt/rust/bin/rustdoc \
    /bin/bash /work/sdk-pending-multipart/tests/build-installed-historical-pending-multipart-inner.sh
' build "$task_root"
