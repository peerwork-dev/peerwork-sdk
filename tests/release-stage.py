"""Offline metadata-only release repacking, source association and refusal gates.

Uses unchanged real c5e GNU x64 inputs; it does not rebuild their binaries.
"""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/release'))
import assets,stage,version
COHORT=Path(sys.argv.pop(1))
METADATA=Path(sys.argv.pop(1))

class StageGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temporary.cleanup)
        cls.work=Path(cls.temporary.name)
        source=COHORT/'rootfs/work/sdk-current-c5e7a3d'
        cls.cli=source/'target/release/peerwork'
        cls.wheel=source/'dist/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl'
        cls.wrapper=source/'dist/npm/peerwork-agent-sdk-0.0.1.tgz'
        cls.platform=source/'dist/npm/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz'
        cls.metadata=json.loads(METADATA.read_text())
        cls.bundle=cls.work/'first'
        cls.manifest=stage.stage(ROOT,'linux-x64-gnu',cls.cli,cls.wheel,cls.wrapper,cls.platform,cls.metadata,cls.bundle)
    def copy(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        destination=Path(temporary.name)/'bundle';shutil.copytree(self.bundle,destination);return destination
    def reseal(self,directory):
        manifest=json.loads((directory/'release.json').read_text())
        manifest['assets']={name:value for name,value in assets.inventory(directory).items() if name not in {'release.json','SHA256SUMS'}}
        (directory/'release.json').write_bytes(assets.wire(manifest))
        (directory/'SHA256SUMS').write_text(''.join(value['sha256']+'  '+name+'\n' for name,value in sorted(assets.inventory(directory).items()) if name!='SHA256SUMS'))
    def test_exact_source_bundle_and_all_compiled_bytes_preserved(self):
        result=stage.verify(self.bundle,ROOT);self.assertEqual(result['target'],'linux-x64-gnu');self.assertEqual(result['unsigned'],True)
        for name,data in assets.wheel_members(self.wheel).items():
            if name.endswith(('.so','.pyd')):self.assertEqual(assets.wheel_members(self.bundle/self.wheel.name)[name],data)
        self.assertEqual(assets.tar_members(self.bundle/self.platform.name)['package/index.node'],assets.tar_members(self.platform)['package/index.node'])
        self.assertEqual(assets.tar_members(self.bundle/result['package_assets'][3])['peerwork'],self.cli.read_bytes())
    def test_independent_repacking_is_exact_without_native_build_claim(self):
        second=self.work/'second';stage.stage(ROOT,'linux-x64-gnu',self.cli,self.wheel,self.wrapper,self.platform,self.metadata,second)
        self.assertEqual(assets.compare(self.bundle,second)['files'],8)
    def test_checksum_and_extra_file_refuse(self):
        directory=self.copy();(directory/'sbom.spdx.json').write_bytes(b'changed')
        with self.assertRaises(version.ReleaseError):stage.verify(directory,ROOT)
        directory=self.copy();(directory/'unexpected').write_bytes(b'added')
        with self.assertRaises(version.ReleaseError):stage.verify(directory,ROOT)
    def test_resealed_payload_and_record_substitution_refuse(self):
        directory=self.copy();path=directory/self.wheel.name;files=assets.wheel_members(path)
        notice=next(name for name in files if name.startswith('peerwork/third_party/licenses/'));files[notice]=b'changed source notice'
        with zipfile.ZipFile(path,'w') as archive:
            for name,data in files.items():archive.writestr(name,data)
        self.reseal(directory)
        with self.assertRaises(version.ReleaseError):stage.verify(directory,ROOT)
        directory=self.copy();path=directory/self.wheel.name;files=assets.wheel_members(path)
        record=next(name for name in files if name.endswith('.dist-info/RECORD'));files[record]=b'peerwork/py.typed,,\n'
        with zipfile.ZipFile(path,'w') as archive:
            for name,data in files.items():archive.writestr(name,data)
        self.reseal(directory)
        with self.assertRaisesRegex(version.ReleaseError,'RECORD'):stage.verify(directory,ROOT)
    def test_resealed_cli_extra_payload_refuses(self):
        directory=self.copy();path=directory/self.manifest['package_assets'][3];files=assets.tar_members(path);files['unexpected']=b'added'
        assets.deterministic_tar(path,{name:(data,0o644) for name,data in files.items()},self.manifest['source_date_epoch']);self.reseal(directory)
        with self.assertRaisesRegex(version.ReleaseError,'CLI release archive closure'):stage.verify(directory,ROOT)
    def test_wrong_source_and_named_target_refuse(self):
        directory=self.copy();manifest=json.loads((directory/'release.json').read_text());manifest['source_commit']='0'*40;(directory/'release.json').write_bytes(assets.wire(manifest));self.reseal(directory)
        with self.assertRaisesRegex(version.ReleaseError,'identity'):stage.verify(directory,ROOT)
        incomplete=self.work/'incomplete';incomplete.mkdir();shutil.copytree(self.bundle,incomplete/'linux-x64-gnu')
        with self.assertRaisesRegex(version.ReleaseError,'seven-target'):stage.assemble(ROOT,incomplete,self.work/'rejected','v0.0.1')
        self.assertFalse((self.work/'rejected').exists())
    def test_existing_output_and_wrong_tag_refuse(self):
        with self.assertRaisesRegex(version.ReleaseError,'fresh'):stage.stage(ROOT,'linux-x64-gnu',self.cli,self.wheel,self.wrapper,self.platform,self.metadata,self.bundle)
        with self.assertRaisesRegex(version.ReleaseError,'tag'):stage.assemble(ROOT,self.work,self.work/'wrong-tag','v0.0.2')
if __name__=='__main__':unittest.main()
