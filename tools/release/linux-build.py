"""Native Linux release container bootstrap with immutable input checksums."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
from version import ReleaseError,check
from build import service_gate_config

def download(url,path,digest):
    if not re.fullmatch('[0-9a-f]{64}',digest):raise ReleaseError('missing pinned bootstrap checksum')
    value=hashlib.sha256()
    with urllib.request.urlopen(url,timeout=60) as response,path.open('wb') as stream:
        while data:=response.read(1024*1024):stream.write(data);value.update(data)
    if value.hexdigest()!=digest:raise ReleaseError('Linux bootstrap input checksum mismatch')

def rustup_installer_url(inputs,target):
    pinned=inputs.get('rustup','')
    if not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+',pinned):
        raise ReleaseError('immutable Rust bootstrap version required')
    triple=inputs['linux'][target]['rust_target']
    if not re.fullmatch(r'(x86_64|aarch64)-unknown-linux-(gnu|musl)',triple):
        raise ReleaseError('invalid Rust bootstrap target')
    return 'https://static.rust-lang.org/rustup/archive/'+pinned+'/'+triple+'/rustup-init'

def launch(root,target,tag):
    service_gate_config(os.environ)
    check(root,tag);inputs=json.loads((root/'tools/release/build-inputs.json').read_text());p=inputs['linux'][target]
    bootstrap=root/'.release-bootstrap';bootstrap.mkdir(exist_ok=True)
    installer=bootstrap/'rustup-init'
    download(rustup_installer_url(inputs,target),installer,p['rustup_sha256']);installer.chmod(0o755)
    if target.endswith('gnu'):
        image=p['image']
        if not re.fullmatch(r'quay.io/pypa/manylinux_2_28_(x86_64|aarch64)@sha256:[0-9a-f]{64}',image):raise ReleaseError('immutable manylinux2.28 image required')
        node=bootstrap/'node.tar.xz';download('https://nodejs.org/dist/v'+inputs['node']+'/node-v'+inputs['node']+'-linux-'+p['node_arch']+'.tar.xz',node,p['node_sha256'])
        prefix='''test "$(getconf GNU_LIBC_VERSION)" = "glibc 2.28"
export PATH="/opt/rh/gcc-toolset-14/root/usr/bin:/opt/python/cp311-cp311/bin:$PATH"
mkdir -p /tmp/release-node
tar --no-same-owner -xJf /work/sdk/.release-bootstrap/node.tar.xz -C /tmp/release-node --strip-components=1
export PATH="/tmp/release-node/bin:$PATH"
'''
    else:
        archive=bootstrap/'alpine.tar.gz';download('https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/'+p['arch']+'/alpine-minirootfs-'+p['alpine']+'-'+p['arch']+'.tar.gz',archive,p['rootfs_sha256'])
        image='peerwork-release-alpine:'+p['arch']
        subprocess.run(['docker','import',str(archive),image],check=True)
        prefix='''apk add --no-cache build-base cmake perl python3 py3-pip nodejs npm git curl ca-certificates openssl-dev pkgconf binutils clang20 libc++ libc++-dev libc++-static llvm-libunwind-dev llvm-libunwind-static patchelf
python3 -c 'import pathlib,re; rows=[dict(line.split(":",1) for line in block.splitlines() if ":" in line) for block in pathlib.Path("/lib/apk/db/installed").read_text().split("\\n\\n")]; found={row.get("P"):row.get("V","") for row in rows}; raise SystemExit(0 if all(re.fullmatch("20[.]1[.]8-r[0-9]+",found.get(name,"")) for name in ["libc++","llvm-libunwind"]) else "bundled LLVM version differs from pinned source notice")'
python3 -m venv /tmp/release-python
export PATH="/tmp/release-python/bin:$PATH"
export PEERWORK_MUSL_CXX_LIB_DIR=/usr/lib
'''
    script='''set -eu
test "$(uname -m)" = "$PEERWORK_BUILD_ARCH"
git config --global --add safe.directory /work/sdk
'''+prefix+'''export RUSTUP_HOME=/tmp/release-rustup CARGO_HOME=/tmp/release-cargo
/work/sdk/.release-bootstrap/rustup-init -y --no-modify-path --default-toolchain 1.89.0 --profile minimal
export PATH="$RUSTUP_HOME/toolchains/1.89.0-$PEERWORK_RUST_TARGET/bin:$PATH"
export LD_LIBRARY_PATH="$RUSTUP_HOME/toolchains/1.89.0-$PEERWORK_RUST_TARGET/lib"
python -m pip install maturin==1.15.0
python tools/release/build.py --target "$PEERWORK_BUILD_TARGET" --tag "$PEERWORK_RELEASE_TAG" --output "/work/sdk/.release-ci/$PEERWORK_BUILD_TARGET"
'''
    shell='/bin/bash' if target.endswith('gnu') else '/bin/sh'
    gate_names=['PEERWORK_RELEASE_SERVICE_GATE','PEERWORK_RELEASE_SERVICE_ORIGIN',
                'PEERWORK_RELEASE_SERVICE_SOURCE_COMMIT','PEERWORK_RELEASE_SERVICE_WRITE_SCOPE']
    gate_env=[arg for name in gate_names for arg in ('-e',name)]
    subprocess.run(['docker','run','--rm','-v',str(root)+':/work/sdk','-w','/work/sdk','-e','PEERWORK_BUILD_ARCH='+p['arch'],'-e','PEERWORK_RUST_TARGET='+p['rust_target'],'-e','PEERWORK_BUILD_TARGET='+target,'-e','PEERWORK_RELEASE_TAG='+tag,*gate_env,image,shell,'-ec',script],check=True)
    if target.endswith('musl'):
        runtime='''set -eu
apk add --no-cache python3 py3-pip nodejs npm binutils ca-certificates
test ! -e /usr/lib/libc++.so.1
test ! -e /usr/lib/libc++abi.so.1
test ! -e /usr/lib/libunwind.so.1
unset LD_LIBRARY_PATH PYTHONPATH PYTHONHOME ICU_DATA
bundle="/work/sdk/.release-ci/$PEERWORK_BUILD_TARGET"
python3 -m venv --without-pip /tmp/release-consumer
site=$(/tmp/release-consumer/bin/python -I -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
python3 -m pip install --no-index --no-deps --target "$site" "$bundle"/*.whl
version=$(/tmp/release-consumer/bin/python -I -c 'import peerwork; print(peerwork.version())')
mkdir -p /tmp/node-consumer /tmp/cli
printf '%s\\n' '{"name":"release-consumer","version":"0.0.0","private":true}' >/tmp/node-consumer/package.json
npm install --prefix /tmp/node-consumer --offline --ignore-scripts --omit=optional --no-audit --no-fund "$bundle/peerwork-agent-sdk-$version.tgz" "$bundle/peerwork-agent-sdk-$PEERWORK_BUILD_TARGET-$version.tgz"
node bindings/node/scripts/offline-smoke.mjs /tmp/node-consumer
tar -xzf "$bundle/peerwork-$version-$PEERWORK_BUILD_TARGET.tar.gz" -C /tmp/cli
if readelf -d /tmp/cli/peerwork | grep -q NEEDED; then exit 1; fi
if readelf -l /tmp/cli/peerwork | grep -q INTERP; then exit 1; fi
/tmp/cli/peerwork version
mkdir -m 700 '/tmp/release protected identity Ω with spaces'
python3 tests/installed-protected-identity-smoke.py --python /tmp/release-consumer/bin/python --node "$(command -v node)" --node-consumer /tmp/node-consumer --cli /tmp/cli/peerwork --state-dir '/tmp/release protected identity Ω with spaces'
if [ "${PEERWORK_RELEASE_SERVICE_GATE:-0}" = 1 ]; then
    PEERWORK_TEST_ORIGIN="$PEERWORK_RELEASE_SERVICE_ORIGIN" \
    PEERWORK_TEST_SDK_ROOT=/work/sdk \
    PEERWORK_TEST_STATE='/tmp/release protected identity Ω with spaces/service' \
    PEERWORK_TEST_NODE="$(command -v node)" \
    PEERWORK_TEST_NODE_PACKAGE=/tmp/node-consumer/node_modules/@peerwork/agent-sdk \
    PEERWORK_TEST_CLI=/tmp/cli/peerwork \
    PEERWORK_TEST_OWNER_SOURCE_SHA256="$(sha256sum crates/runtime/src/secure_owner_create.rs | cut -d ' ' -f 1)" \
    /tmp/release-consumer/bin/python tests/installed-native-owner-adopter-workflow.py
fi
'''
        subprocess.run(['docker','run','--rm','-v',str(root)+':/work/sdk:ro','-w','/work/sdk','-e','PEERWORK_BUILD_TARGET='+target,*gate_env,image,'/bin/sh','-ec',runtime],check=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);parser.add_argument('--target',choices=['linux-x64-gnu','linux-arm64-gnu','linux-x64-musl','linux-arm64-musl'],required=True);parser.add_argument('--tag',required=True);args=parser.parse_args()
    try:launch(args.root,args.target,args.tag)
    except (ReleaseError,subprocess.CalledProcessError) as error:parser.exit(2,'release Linux builder refused: '+str(error)+'\n')
