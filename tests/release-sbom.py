"""Offline actual locked-source SBOM and notice substitution regressions."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/release'))
import assets,notices,sbom,version
METADATA=Path(sys.argv.pop(1))
SOURCE='aabc909cd330f10294e2b97d0303d509b9073bde'

class SbomGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.metadata=json.loads(METADATA.read_text())
    def generate(self,metadata=None):return sbom.generate(ROOT,'linux-x64-gnu',metadata or deepcopy(self.metadata),SOURCE,1791979200)
    def test_real_locked_source_inventory_and_determinism(self):
        first=self.generate();second=self.generate()
        self.assertEqual(assets.wire(first[0]),assets.wire(second[0]));self.assertEqual(first[1:],second[1:])
        self.assertEqual(first[0]['spdxVersion'],'SPDX-2.3');self.assertEqual(first[1]['unknown_bundled_licenses'],[])
        self.assertTrue(any(p['name']=='ICU4C' for p in first[0]['packages']));self.assertFalse(any('LLVM' in p['name'] for p in first[0]['packages']))
        self.assertNotIn(str(ROOT),assets.wire(first[0]).decode());self.assertGreater(len(first[2]),0)
    def test_claimed_license_cannot_replace_actual_source_declaration(self):
        m=deepcopy(self.metadata);p=next(p for p in m['packages'] if p['name']=='aes-gcm');p['license']='MIT'
        with self.assertRaises(version.ReleaseError):self.generate(m)
    def test_unknown_license_refuses(self):
        m=deepcopy(self.metadata);p=next(p for p in m['packages'] if p['name']=='aes-gcm');p['license']=None
        with self.assertRaises(version.ReleaseError):self.generate(m)
    def test_spdx_legacy_spelling_is_normalized_without_unknown_promotion(self):
        self.assertEqual(sbom.license_expression('MIT/Apache-2.0'),'MIT OR Apache-2.0')
        with self.assertRaises(version.ReleaseError):sbom.license_expression('UnknownLicense-1.0')
        with self.assertRaises(version.ReleaseError):sbom.license_expression('(MIT OR Apache-2.0')
    def test_exact_upstream_notice_is_component_bound(self):
        document,inventory,_=self.generate()
        napi=next(p for p in inventory['components'] if p['component']=='napi')
        self.assertEqual(napi['notices'][0]['source']['revision'],'f2178312d0e3e07beecc19836b91716a229107d3')
        self.assertEqual(napi['notices'][0]['sha256'],'3f1ce66533302df3a32edbfdfc0b78f0dd34659e4c1f5817162e5ea3c2297215')
    def test_incomplete_graph_and_wrong_workspace_refuse(self):
        m=deepcopy(self.metadata);m['resolve']['nodes'].append(dict(id='unavailable',dependencies=[]))
        with self.assertRaises(version.ReleaseError):self.generate(m)
        m=deepcopy(self.metadata);m['workspace_root']='/tmp/unrelated-source'
        with self.assertRaises(version.ReleaseError):self.generate(m)
    def test_changed_dependency_notice_refuses_against_locked_crate(self):
        m=deepcopy(self.metadata);p=next(p for p in m['packages'] if p['name']=='aead');original=Path(p['manifest_path']).parent
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'registry/src/index-fixture'/original.name;directory.mkdir(parents=True)
            for name in ['Cargo.toml',*[x.name for x in original.iterdir() if x.is_file() and x.name.startswith('LICENSE')]]:shutil.copyfile(original/name,directory/name)
            cache=directory.parent.parent.parent/'cache'/directory.parent.name;cache.mkdir(parents=True)
            actual=original.parent.parent.parent/'cache'/original.parent.name/(original.name+'.crate');shutil.copyfile(actual,cache/actual.name)
            license_path=next(directory.glob('LICENSE*'));license_path.write_bytes(b'substituted notice')
            p['manifest_path']=str(directory/'Cargo.toml')
            with self.assertRaises(version.ReleaseError):self.generate(m)
    def test_platform_notice_readme_and_llvm_substitution_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'native.tgz';target='linux-x64-musl'
            files={'package/LICENSE':((ROOT/'bindings/node/LICENSE').read_bytes(),0o644),
                'package/README.md':(('# @peerwork/agent-sdk-'+target+'\n\nExperimental platform binary. No verified operations yet.\n').encode(),0o644),
                'package/LLVM-LICENSE.txt':((ROOT/'third_party/llvm-20.1.8-LICENSE.txt').read_bytes(),0o644)}
            assets.deterministic_tar(path,files,1791979200);self.assertEqual(notices.platform(ROOT,target,path)['exact_source_notices'],3)
            for name in list(files):
                changed=dict(files);changed[name]=(b'substitution',0o644);assets.deterministic_tar(path,changed,1791979200)
                with self.assertRaises(version.ReleaseError):notices.platform(ROOT,target,path)
if __name__=='__main__':unittest.main()
