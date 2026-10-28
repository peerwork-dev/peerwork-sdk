"""Release builder called inside the selected native CI runner/container.

No prebuilt SDK artifact or caller-supplied compiler-source value is accepted.
The reusable CI workflow authenticates this exact checkout and resulting bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import venv
from urllib.parse import urlsplit
import stage
from version import TARGETS,ReleaseError,check

TRIPLES={'linux-x64-gnu':'x86_64-unknown-linux-gnu','linux-arm64-gnu':'aarch64-unknown-linux-gnu','linux-x64-musl':'x86_64-unknown-linux-musl','linux-arm64-musl':'aarch64-unknown-linux-musl','darwin-x64':'x86_64-apple-darwin','darwin-arm64':'aarch64-apple-darwin','win32-x64-msvc':'x86_64-pc-windows-msvc'}

def run(args,root,env=None):
    subprocess.run([str(arg) for arg in args],cwd=root,env=env,check=True)

def service_gate_config(env):
    if env.get('PEERWORK_RELEASE_SERVICE_GATE')!='1':
        if env.get('PEERWORK_RELEASE_SERVICE_GATE') not in (None,'0'):
            raise ReleaseError('release service gate selector must be 0 or 1')
        return None
    origin=env.get('PEERWORK_RELEASE_SERVICE_ORIGIN','')
    source=env.get('PEERWORK_RELEASE_SERVICE_SOURCE_COMMIT','')
    scope=env.get('PEERWORK_RELEASE_SERVICE_WRITE_SCOPE','')
    try:
        parsed=urlsplit(origin)
        parsed.port
    except ValueError as error:
        raise ReleaseError('service gate origin is malformed') from error
    if (parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('','/') or parsed.query or parsed.fragment
            or (parsed.scheme=='http' and parsed.hostname not in ('localhost','127.0.0.1','::1'))):
        raise ReleaseError('service gate requires an explicit HTTPS or loopback HTTP service origin')
    if source and not re.fullmatch(r'[0-9a-f]{40}',source):
        raise ReleaseError('service gate source commit must be a full lowercase Git commit when supplied')
    if scope!='new-public-workspace':
        raise ReleaseError('service gate requires explicit new-public-workspace write scope')
    return origin

def build(root: Path,target: str,output: Path,tag: str):
    service_origin=service_gate_config(os.environ)
    identity=check(root,tag);revision,epoch=stage.source(root)
    if target not in TRIPLES:raise ReleaseError('unknown native release build target')
    host=subprocess.check_output(['rustc','-vV'],text=True)
    if 'release: 1.89.0\n' not in host or 'host: '+TRIPLES[target]+'\n' not in host:raise ReleaseError('release requires selected native Rust1.89 host')
    if sys.version_info.major!=3 or sys.version_info.minor not in range(11,15):raise ReleaseError('release requires a supported CPython3.11–3.14 interpreter')
    if subprocess.check_output(['node','-p','process.arch'],text=True).strip()!=target.split('-')[1]:raise ReleaseError('native Node architecture mismatch')
    if target.startswith('darwin') and os.environ.get('MACOSX_DEPLOYMENT_TARGET')!='11.0':raise ReleaseError('macOS release requires explicit deployment target11.0')
    if output.exists():raise ReleaseError('native build output must be fresh')
    work=root/'.release-build';work.mkdir(exist_ok=True)
    env=dict(os.environ,SOURCE_DATE_EPOCH=str(epoch),CARGO_TARGET_DIR=str(work/'shared-target'))
    flags='--remap-path-prefix='+str(root)+'=/peerwork/src --remap-path-prefix='+str(work)+'=/peerwork/build'
    env['RUSTFLAGS']=flags+(' -C target-feature=-crt-static' if target.endswith('musl') else '')
    if not target.startswith('win32'):
        for name in ['CFLAGS','CXXFLAGS']:env[name]='-ffile-prefix-map='+str(root)+'=/peerwork/src -ffile-prefix-map='+str(work)+'=/peerwork/build'
    run(['cargo','test','--workspace','--locked'],root,env)
    run(['cargo','build','--release','--locked','-p','peerwork-node-native',*([] if target.endswith('musl') else ['-p','peerwork-cli'])],root,env)
    python=root/'bindings/python'
    compatibility=['--compatibility','musllinux_1_2' if target.endswith('musl') else 'manylinux_2_28'] if target.startswith('linux') else []
    wheels=work/'wheels';wheels.mkdir()
    run(['maturin','build','--release','--locked',*compatibility,'--interpreter',sys.executable,'--out',wheels],python,env)
    wheel_list=list(wheels.glob('*.whl'))
    if len(wheel_list)!=1:raise ReleaseError('exactly one native wheel required')
    run([sys.executable,'tests/verify-typed-wheel.py',wheel_list[0]],root,env)
    lib='peerwork_node_native.dll' if target.startswith('win32') else 'libpeerwork_node_native.dylib' if target.startswith('darwin') else 'libpeerwork_node_native.so'
    dist=work/'node';dist.mkdir()
    run(['node','bindings/node/scripts/package-platform.mjs',target,Path(env['CARGO_TARGET_DIR'])/'release'/lib,dist],root,env)
    npm=shutil.which('npm.cmd' if target.startswith('win32') else 'npm')
    if not npm:raise ReleaseError('native npm pack executable required')
    run([npm,'pack','./bindings/node','--pack-destination',dist,'--offline'],root,env)
    run([npm,'pack',dist/('agent-sdk-'+target),'--pack-destination',dist,'--offline'],root,env)
    version=identity['version'];wrapper=dist/('peerwork-agent-sdk-'+version+'.tgz');native=dist/('peerwork-agent-sdk-'+target+'-'+version+'.tgz')
    cli=Path(env['CARGO_TARGET_DIR'])/'release'/('peerwork.exe' if target.startswith('win32') else 'peerwork')
    if target.endswith('musl'):
        static=dict(env,CARGO_TARGET_DIR=str(work/'static-target'),RUSTFLAGS=flags,PEERWORK_MUSL_STATIC_CXX='1')
        run(['cargo','build','--release','--locked','-p','peerwork-cli'],root,static)
        cli=Path(static['CARGO_TARGET_DIR'])/'release/peerwork'
        if 'NEEDED' in subprocess.check_output(['readelf','-d',cli],text=True) or 'INTERP' in subprocess.check_output(['readelf','-l',cli],text=True):raise ReleaseError('musl CLI must be standalone static')
    consumer=work/'node-consumer';consumer.mkdir();(consumer/'package.json').write_text('{"name":"release-consumer","version":"0.0.0","private":true}\n')
    run([npm,'install','--prefix',consumer,'--offline','--ignore-scripts','--omit=optional','--no-audit','--no-fund',wrapper,native],root,env)
    smoke=dict(env)
    for name in ['LD_LIBRARY_PATH','PYTHONPATH','PYTHONHOME','ICU_DATA','RUSTFLAGS']:smoke.pop(name,None)
    run(['node','bindings/node/scripts/offline-smoke.mjs',consumer],root,smoke)
    venv_dir=work/'python-consumer';venv.create(venv_dir,with_pip=True)
    interpreter=venv_dir/('Scripts/python.exe' if target.startswith('win32') else 'bin/python')
    run([interpreter,'-m','pip','install','--no-index','--no-deps',wheel_list[0]],root,env)
    run([interpreter,'-I','-c','import peerwork,sys; assert peerwork.version()==sys.argv[1]; assert peerwork.capabilities()["version"]==sys.argv[1]; assert callable(peerwork.ProtocolSession) and callable(peerwork.ProtocolSessionError)',version],root,smoke)
    run([cli,'version'],root,smoke)
    if target.endswith('gnu'):
        import zipfile
        with zipfile.ZipFile(wheel_list[0]) as archive:
            members=[name for name in archive.namelist() if name.startswith('peerwork/') and name.endswith('.so')]
            if len(members)!=1:raise ReleaseError('GNU wheel native subject missing')
            native_wheel=work/'wheel-native.so';native_wheel.write_bytes(archive.read(members[0]))
        for binary in [cli,Path(env['CARGO_TARGET_DIR'])/'release'/lib,native_wheel]:
            symbols=subprocess.check_output(['readelf','--version-info',binary],text=True)
            versions=[tuple(int(part or 0) for part in match) for match in re.findall(r'\bGLIBC_(\d+)\.(\d+)(?:\.(\d+))?\b',symbols)]
            if any(value>(2,28,0) for value in versions):raise ReleaseError('native GNU artifact exceeds declared glibc2.28 floor')
    # The test itself exercises Unicode protected state and no-replace imports.
    state=work/'protected identity Ω with spaces'
    if target.startswith('win32'):
        acl_env=dict(env,PEERWORK_RELEASE_STATE=str(state))
        run(['pwsh','-NoProfile','-NonInteractive','-Command','$p=$env:PEERWORK_RELEASE_STATE; [void][System.IO.Directory]::CreateDirectory($p); $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $acl=New-Object System.Security.AccessControl.DirectorySecurity; $acl.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;$sid)"); Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop'],root,acl_env)
    else:state.mkdir(mode=0o700)
    run([sys.executable,'tests/installed-protected-identity-smoke.py','--python',interpreter,'--node',shutil.which('node'),'--node-consumer',consumer,'--cli',cli,'--state-dir',state],root,smoke)
    if service_origin and not target.endswith('musl'):
        gate_env=dict(smoke,PEERWORK_TEST_ORIGIN=service_origin,
                      PEERWORK_TEST_SDK_ROOT=str(root),PEERWORK_TEST_STATE=str(state/'service'),
                      PEERWORK_TEST_NODE=shutil.which('node'),
                      PEERWORK_TEST_NODE_PACKAGE=str(consumer/'node_modules/@peerwork/agent-sdk'),
                      PEERWORK_TEST_CLI=str(cli),
                      PEERWORK_TEST_OWNER_SOURCE_SHA256=hashlib.sha256((root/'crates/runtime/src/secure_owner_create.rs').read_bytes()).hexdigest())
        run([interpreter,'tests/installed-native-owner-adopter-workflow.py'],root,gate_env)
    metadata=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1','--filter-platform',TRIPLES[target]],cwd=root,env=env,text=True))
    result=stage.stage(root,target,cli,wheel_list[0],wrapper,native,metadata,output,revision)
    if not result['release_eligible']:raise ReleaseError('builder source changed before packaging')
    stage.verify(output,root)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);parser.add_argument('--target',choices=TARGETS,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--tag',required=True);args=parser.parse_args()
    try:result=build(args.root,args.target,args.output,args.tag)
    except (ReleaseError,subprocess.CalledProcessError) as error:parser.exit(2,'release native builder refused: '+str(error)+'\n')
    print(json.dumps(dict(source_commit=result['source_commit'],target=result['target'],declared_source_agrees=result['release_eligible']),sort_keys=True))
if __name__=='__main__':main()
