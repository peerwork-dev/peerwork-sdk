"""Offline adversarial release guards. Synthetic packages are not platform runs."""
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/release'))
import assets
import version

class ReleaseGuards(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)/'source';self.root.mkdir()
        paths=['Cargo.toml','Cargo.lock','bindings/python/pyproject.toml','bindings/node/package.json',*['bindings/node/'+p for p in json.loads((ROOT/'bindings/node/package.json').read_text())['files']]]
        paths += [p+'/Cargo.toml' for p in version.read_toml(ROOT/'Cargo.toml')['workspace']['members']]
        for name in paths:
            dest=self.root/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
        version.sync(self.root,'0.0.1')
        self.output=Path(self.temporary.name)/'assets';self.output.mkdir()
        self.binary=bytearray(64);self.binary[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',self.binary,18,62)
        self.cli=self.output/'peerwork';self.cli.write_bytes(self.binary)
        self.wheel=self.output/'peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl'
        self.wheel_files={'peerwork/__init__.py':b'fixture\n','peerwork/py.typed':b'', 'peerwork/_peerwork_native.abi3.so':bytes(self.binary),
            'peerwork_sdk-0.0.1.dist-info/METADATA':b'Metadata-Version: 2.4\nName: peerwork-sdk\nVersion: 0.0.1\n',
            'peerwork_sdk-0.0.1.dist-info/WHEEL':b'Wheel-Version: 1.0\nTag: cp311-abi3-manylinux_2_28_x86_64\n'}
        self.write_wheel()
        metadata=json.loads((self.root/'bindings/node/package.json').read_text())
        self.wrapper=self.output/'wrapper.tgz'
        self.wrapper_files={'package/package.json':json.dumps(metadata).encode()}
        self.wrapper_files.update({'package/'+p:(self.root/'bindings/node'/p).read_bytes() for p in metadata['files']})
        self.write_tar(self.wrapper,self.wrapper_files)
        self.platform=self.output/'platform.tgz'
        self.platform_meta=dict(name='@peerwork/agent-sdk-linux-x64-gnu',version='0.0.1',description='fixture only',license=metadata['license'],repository=metadata['repository'],os=['linux'],cpu=['x64'],libc=['glibc'],files=['index.node','index.cjs','LICENSE','README.md'],main='index.cjs')
        self.platform_files={'package/index.node':bytes(self.binary),'package/index.cjs':b"'use strict';\nmodule.exports = require('./index.node');\n",'package/README.md':b'fixture','package/LICENSE':(self.root/'bindings/node/LICENSE').read_bytes()}
        self.write_platform()
    def write_tar(self,path,files):assets.deterministic_tar(path,{n:(data,0o644) for n,data in files.items()},1234567890)
    def write_platform(self):
        self.platform_files['package/package.json']=json.dumps(self.platform_meta).encode();self.write_tar(self.platform,self.platform_files)
    def write_wheel(self):
        content=dict(self.wheel_files);record='peerwork_sdk-0.0.1.dist-info/RECORD';out=io.StringIO();writer=csv.writer(out,lineterminator='\n')
        for name,data in sorted(content.items()):writer.writerow([name,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode(),len(data)])
        writer.writerow([record,'','']);content[record]=out.getvalue().encode()
        with zipfile.ZipFile(self.wheel,'w') as archive:
            for name,data in content.items():archive.writestr(name,data)
    def inspect(self):return assets.inspect(self.root,'linux-x64-gnu',self.cli,self.wheel,self.wrapper,self.platform)
    def test_consistent_metadata_and_exact_artifact_shape(self):
        self.assertEqual(version.check(self.root,'v0.0.1')['version'],'0.0.1');self.assertEqual(self.inspect()['target'],'linux-x64-gnu')
    def test_tag_and_optional_platform_drift_refuse(self):
        with self.assertRaises(version.ReleaseError):version.check(self.root,'v0.0.2')
        p=self.root/'bindings/node/package.json';m=json.loads(p.read_text());m['optionalDependencies']['@peerwork/agent-sdk-linux-arm64-gnu']='0.0.2';p.write_text(json.dumps(m))
        with self.assertRaises(version.ReleaseError):version.check(self.root)
    def test_explicit_version_update_preserves_nonworkspace_lock_and_metadata(self):
        original=version.read_toml(self.root/'Cargo.lock')['package'];result=version.sync(self.root,'1.2.3');changed=version.read_toml(self.root/'Cargo.lock')['package']
        self.assertEqual([p for p in original if 'source' in p],[p for p in changed if 'source' in p]);self.assertEqual(result['version'],'1.2.3');self.assertEqual(version.check(self.root,'v1.2.3')['version'],'1.2.3')
    def test_missing_platform_is_not_automatically_repaired(self):
        p=self.root/'bindings/node/package.json';m=json.loads(p.read_text());del m['optionalDependencies']['@peerwork/agent-sdk-darwin-arm64'];p.write_text(json.dumps(m));before=(self.root/'Cargo.toml').read_bytes()
        with self.assertRaises(version.ReleaseError):version.sync(self.root,'1.2.3')
        self.assertEqual((self.root/'Cargo.toml').read_bytes(),before)
    def test_python_static_override_and_core_noninherited_version_refuse(self):
        p=self.root/'bindings/python/pyproject.toml';original=p.read_text();p.write_text(original.replace('dynamic = ["version"]','version = "0.0.1"'))
        with self.assertRaises(version.ReleaseError):version.check(self.root)
        p.write_text(original);core=self.root/'crates/core/Cargo.toml';core.write_text(core.read_text().replace('version.workspace = true','version = "0.0.1"',1))
        with self.assertRaises(version.ReleaseError):version.check(self.root)
    def test_platform_packager_derives_updated_root_version(self):
        version.sync(self.root,'1.2.3')
        script=self.root/'bindings/node/scripts/package-platform.mjs';script.parent.mkdir();shutil.copyfile(ROOT/'bindings/node/scripts/package-platform.mjs',script)
        output=self.output/'packaged'
        result=subprocess.run([os.environ.get('PEERWORK_TEST_NODE','node'),str(script),'linux-x64-gnu',str(self.cli),str(output)],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        metadata=json.loads((output/'agent-sdk-linux-x64-gnu/package.json').read_text())
        self.assertEqual(metadata['version'],'1.2.3');self.assertEqual(metadata['name'],'@peerwork/agent-sdk-linux-x64-gnu')
    def test_wrong_wheel_version_and_platform_refuse(self):
        self.wheel_files['peerwork_sdk-0.0.1.dist-info/METADATA']=b'Name: peerwork-sdk\nVersion: 0.0.2\n';self.write_wheel()
        with self.assertRaises(version.ReleaseError):self.inspect()
        self.wheel_files['peerwork_sdk-0.0.1.dist-info/METADATA']=b'Name: peerwork-sdk\nVersion: 0.0.1\n';self.wheel_files['peerwork_sdk-0.0.1.dist-info/WHEEL']=b'Tag: cp311-abi3-win_amd64\n';self.write_wheel()
        with self.assertRaises(version.ReleaseError):self.inspect()
    def test_record_tamper_refuses(self):
        with zipfile.ZipFile(self.wheel) as archive:files={n:archive.read(n) for n in archive.namelist()}
        files['peerwork/py.typed']=b'tampered'
        with zipfile.ZipFile(self.wheel,'w') as archive:
            for name,data in files.items():archive.writestr(name,data)
        with self.assertRaises(version.ReleaseError):self.inspect()
    def test_all_release_wheel_profiles_and_build_tag(self):
        for target,platform in assets.WHEEL_PLATFORM.items():
            with self.subTest(target=target):
                tag='cp311-abi3-'+platform
                assets.wheel_tags('peerwork_sdk-0.0.1-'+tag+'.whl',[tag],target,'0.0.1')
                assets.wheel_tags('peerwork_sdk-0.0.1-2build_-'+tag+'.whl',[tag],target,'0.0.1')
    def test_wheel_substrings_wrong_floors_and_extra_tags_refuse(self):
        invalid={
            'linux-x64-gnu':['notmanylinux_2_28_x86_64','manylinux_2_28_x86_64_extra','manylinux_2_39_x86_64','manylinux_2_28_aarch64'],
            'linux-arm64-gnu':['manylinux_2_39_aarch64','linux_aarch64','notmanylinux_2_28_aarch64'],
            'linux-x64-musl':['notmusllinux_1_2_x86_64','musllinux_1_1_x86_64'],
            'linux-arm64-musl':['musllinux_1_3_aarch64','musllinux_1_2_aarch64_extra'],
            'darwin-x64':['notmacosx_11_0_x86_64','macosx_12_0_x86_64','macosx_11_0_universal2'],
            'darwin-arm64':['macosx_10_9_arm64','macosx_11_0_arm64_extra'],
            'win32-x64-msvc':['notwin_amd64','win_amd64_extra','win_arm64']}
        for target,platforms in invalid.items():
            for platform in platforms:
                with self.subTest(target=target,platform=platform),self.assertRaises(version.ReleaseError):
                    tag='cp311-abi3-'+platform
                    assets.wheel_tags('peerwork_sdk-0.0.1-'+tag+'.whl',[tag],target,'0.0.1')
        tag='cp311-abi3-manylinux_2_28_x86_64'
        with self.assertRaises(version.ReleaseError):assets.wheel_tags(self.wheel.name,[tag,tag], 'linux-x64-gnu','0.0.1')
        with self.assertRaises(version.ReleaseError):assets.wheel_tags(self.wheel.name,[tag,'cp312-abi3-manylinux_2_28_x86_64'],'linux-x64-gnu','0.0.1')
    def test_filename_internal_tag_disagreement_and_grammar_refuse(self):
        tag='cp311-abi3-manylinux_2_28_x86_64'
        for filename in ['peerwork_sdk-0.0.1-cp312-abi3-manylinux_2_28_x86_64.whl','peerwork_sdk-0.0.1-cp311-abi3-win_amd64.whl','peerwork_sdk-0.0.2-'+tag+'.whl','other-0.0.1-'+tag+'.whl','peerwork_sdk-0.0.1-xbuild-'+tag+'.whl','peerwork_sdk-0.0.1-cp311..cp312-abi3-manylinux_2_28_x86_64.whl']:
            with self.subTest(filename=filename),self.assertRaises(version.ReleaseError):assets.wheel_tags(filename,[tag],'linux-x64-gnu','0.0.1')
        # Exercise the inspector itself with a valid filename but different
        # well-formed internal tags, and the opposite renamed valid wheel.
        self.wheel_files['peerwork_sdk-0.0.1.dist-info/WHEEL']=b'Tag: cp312-abi3-manylinux_2_28_x86_64\n';self.write_wheel()
        with self.assertRaisesRegex(version.ReleaseError,'disagree'):self.inspect()
        self.wheel_files['peerwork_sdk-0.0.1.dist-info/WHEEL']=('Tag: '+tag+'\n').encode();self.write_wheel()
        renamed=self.wheel.with_name('peerwork_sdk-0.0.1-cp312-abi3-manylinux_2_28_x86_64.whl');self.wheel.rename(renamed);self.wheel=renamed
        with self.assertRaisesRegex(version.ReleaseError,'disagree'):self.inspect()
    def test_compressed_filename_expansion_cannot_hide_extra_profile(self):
        filename='peerwork_sdk-0.0.1-cp311.cp312-abi3-manylinux_2_28_x86_64.whl'
        with self.assertRaisesRegex(version.ReleaseError,'disagree'):assets.wheel_tags(filename,['cp311-abi3-manylinux_2_28_x86_64'],'linux-x64-gnu','0.0.1')
        with self.assertRaisesRegex(version.ReleaseError,'profile mismatch'):assets.wheel_tags(filename,['cp311-abi3-manylinux_2_28_x86_64','cp312-abi3-manylinux_2_28_x86_64'],'linux-x64-gnu','0.0.1')
    def test_wrapper_extra_or_substituted_source_refuses(self):
        self.wrapper_files['package/index.cjs']=b'altered loader';self.write_tar(self.wrapper,self.wrapper_files)
        with self.assertRaises(version.ReleaseError):self.inspect()
        self.wrapper_files['package/index.cjs']=(self.root/'bindings/node/index.cjs').read_bytes();self.wrapper_files['package/unexpected']=b'extra';self.write_tar(self.wrapper,self.wrapper_files)
        with self.assertRaises(version.ReleaseError):self.inspect()
    def test_wrong_native_arch_or_install_hook_refuses(self):
        data=bytearray(self.binary);struct.pack_into('<H',data,18,183);self.platform_files['package/index.node']=data;self.write_platform()
        with self.assertRaises(version.ReleaseError):self.inspect()
        self.platform_files['package/index.node']=bytes(self.binary);self.platform_meta['scripts']={'postinstall':'unexpected'};self.write_platform()
        with self.assertRaises(version.ReleaseError):self.inspect()
    def test_traversal_and_symlink_refuse(self):
        with self.assertRaises(version.ReleaseError):assets.safe_name('package/../../secret')
        with tarfile.open(self.platform,'w:gz') as archive:
            item=tarfile.TarInfo('package/index.node');item.type=tarfile.SYMTYPE;item.linkname='/tmp/elsewhere';archive.addfile(item)
        with self.assertRaises(version.ReleaseError):self.inspect()
    def test_deterministic_archive_and_exact_comparator(self):
        a=self.output/'first';b=self.output/'second';a.mkdir();b.mkdir();payload={'peerwork':(bytes(self.binary),0o755),'LICENSE':(b'notice',0o644)}
        assets.deterministic_tar(a/'cli.tar.gz',payload,1234567890);assets.deterministic_tar(b/'cli.tar.gz',dict(reversed(list(payload.items()))),1234567890)
        self.assertEqual(assets.compare(a,b)['files'],1);(b/'cli.tar.gz').write_bytes((b/'cli.tar.gz').read_bytes()+b'x')
        with self.assertRaises(version.ReleaseError):assets.compare(a,b)
    def test_comparator_missing_or_extra_output_refuses(self):
        a=self.output/'a';b=self.output/'b';a.mkdir();b.mkdir();(a/'wheel').write_bytes(b'x');(b/'wheel').write_bytes(b'x');(b/'extra').write_bytes(b'x')
        with self.assertRaises(version.ReleaseError):assets.compare(a,b)
if __name__=='__main__':unittest.main()
