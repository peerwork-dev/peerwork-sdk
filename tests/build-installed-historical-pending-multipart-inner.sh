#!/bin/bash
set -euo pipefail
test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.28'
test "$(/opt/rust/bin/rustc --version | cut -d ' ' -f 2)" = '1.89.0'
cd /work/sdk-pending-multipart
mkdir -p dist/wheels dist/npm
/opt/rust/bin/cargo build --release --locked --offline -p peerwork-cli -p peerwork-node-native
cd bindings/python
/work/tools/bin/maturin build --release --locked --compatibility manylinux_2_28 --out /work/sdk-pending-multipart/dist/wheels
