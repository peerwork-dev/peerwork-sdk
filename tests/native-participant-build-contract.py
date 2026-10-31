"""Candidate source-inventory scope, without building an artifact or using a secret."""
import importlib.util
from pathlib import Path
import sys
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/release'))
import sbom
import version

spec = importlib.util.spec_from_file_location('qualify_participant',ROOT / 'tools/release/qualify-participant.py')
qualifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualifier)


class NativeGraphTests(unittest.TestCase):
    def native_inventory(self):
        release = version.authority(ROOT)
        license_name = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['license']
        packages = [dict(id=name, name=name, version=release, source=None,
                         manifest_path=str(ROOT / member / 'Cargo.toml'), license=license_name)
                    for name, member in [('peerwork-cli', 'crates/cli'),
                                         ('peerwork-runtime', 'crates/runtime'),
                                         ('peerwork-core', 'crates/core')]]
        return dict(version=1, workspace_root=str(ROOT), packages=packages,
                    workspace_members=[p['id'] for p in packages],
                    resolve=dict(nodes=[dict(id=p['id'], dependencies=[])
                                        for p in packages]))

    def test_native_sbom_uses_cargo_version_without_retired_binding_parity(self):
        # Exercise actual source manifests, lock, notices and ICU inputs. The
        # candidate's optional Node package intentionally keeps its old version.
        with patch.object(sbom, 'check', side_effect=AssertionError('legacy release parity used')):
            document, inventory, files = sbom.generate(
                ROOT, 'linux-x64-gnu', self.native_inventory(), 'a' * 40, 0, native=True)
        self.assertEqual(inventory['version'], version.authority(ROOT))
        self.assertEqual({p['name'] for p in document['packages']},
                         {'peerwork-cli', 'peerwork-runtime', 'peerwork-core', 'ICU4C'})
        self.assertTrue(files)
        self.assertTrue(all(row['notices'] for row in inventory['components']))
        self.assertEqual(set(version.check_native(ROOT)['targets']), set(qualifier.TARGETS))

    def test_native_sbom_refuses_wrong_target_wrapper_version_and_license(self):
        cases = [('target', 'invalid selected release'),
                 ('wrapper', 'exactly the CLI/runtime/core'),
                 ('version', 'does not match locked source'),
                 ('license', 'unknown bundled dependency license')]
        for fault, error in cases:
            with self.subTest(fault=fault):
                data = self.native_inventory()
                target = 'linux-x64-gnu'
                if fault == 'target':
                    target = 'linux-arm64-gnu'
                elif fault == 'wrapper':
                    wrapper = dict(data['packages'][0], id='wrapper', name='peerwork-node-native')
                    data['packages'].append(wrapper)
                    data['workspace_members'].append('wrapper')
                    data['resolve']['nodes'].append(dict(id='wrapper', dependencies=[]))
                elif fault == 'version':
                    data['packages'][0]['version'] = '999.0.0'
                else:
                    data['packages'][0]['license'] = 'UNKNOWN'
                with self.assertRaisesRegex(version.ReleaseError, error):
                    sbom.generate(ROOT, target, data, 'a' * 40, 0, native=True)

    def test_windows_imports_reject_dynamic_crt_and_language_runtimes(self):
        good='    KERNEL32.dll\n    api-ms-win-crt-runtime-l1-1-0.dll\n'
        self.assertEqual(qualifier.loader_requirements('win32-x64-msvc',good)['vc_runtime_dlls'],'NOT_IMPORTED')
        for name in ('MSVCP140.dll','VCRUNTIME140_1.dll','concrt140.dll','python3.dll','node.dll','icuuc78.dll'):
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError,'external Windows'):
                qualifier.loader_requirements('win32-x64-msvc',good+'    '+name+'\n')
        with self.assertRaisesRegex(AssertionError,'no imports'):
            qualifier.loader_requirements('win32-x64-msvc','tool failed')
        with self.assertRaisesRegex(AssertionError,'unqualified Windows'):
            qualifier.loader_requirements('win32-x64-msvc',good+'    unreviewed-runtime.dll\n')

    def test_gnu_cpp_abi_cannot_hide_behind_a_compatible_glibc_floor(self):
        deps='(NEEDED) Shared library: [libstdc++.so.6]\n(NEEDED) Shared library: [libc.so.6]'
        symbols='GLIBC_2.2.5 GLIBC_2.28 GLIBCXX_3.4.25 CXXABI_1.3.11'
        result=qualifier.loader_requirements('linux-x64-gnu',deps,symbols)
        self.assertEqual(result['required_symbol_versions']['GLIBCXX'],'3.4.25')
        self.assertEqual(result['cxx_runtime'],'SYSTEM_LIBSTDCXX')
        for extra in ('GLIBC_2.29','GLIBCXX_3.4.26','CXXABI_1.3.12'):
            with self.subTest(extra=extra), self.assertRaisesRegex(AssertionError,'ABI floor exceeded'):
                qualifier.loader_requirements('linux-x64-gnu',deps,symbols+' '+extra)
        with self.assertRaisesRegex(AssertionError,'external Linux'):
            qualifier.loader_requirements('linux-x64-gnu',deps+'\n(NEEDED) Shared library: [libicui18n.so.78]',symbols)

    def test_macos_imports_are_system_libraries_not_a_local_build_tree(self):
        deps='/tmp/peerwork:\n    /usr/lib/libc++.1.dylib (compatibility version 1.0.0, current version 1.0.0)\n'
        self.assertEqual(qualifier.loader_requirements('darwin-arm64',deps)['deployment_target'],'11.0')
        with self.assertRaisesRegex(AssertionError,'external macOS'):
            qualifier.loader_requirements('darwin-arm64',deps+'    @rpath/libicu.dylib (compatibility version 1.0.0, current version 1.0.0)\n')

    def test_cli_json_version_is_a_portable_archive_component(self):
        self.assertEqual(qualifier.candidate_version('{"status":"experimental","version":"0.2.16"}\n'), '0.2.16')
        self.assertEqual(qualifier.candidate_version('{"version":"1.2.3-rc.1+build.4"}'), '1.2.3-rc.1+build.4')
        for raw in ('"0.2.16"', '{}', '{"version":null}', '{"version":"../x"}', '{"version":"1.2.3\\n"}'):
            with self.subTest(raw=raw), self.assertRaises(AssertionError):
                qualifier.candidate_version(raw)

    def fixture(self):
        names = ['peerwork-cli','peerwork-runtime','peerwork-core','peerwork-node-native','external-build-helper']
        packages = [{'id':str(i),'name':name,'source':None if i < 4 else 'registry'} for i,name in enumerate(names)]
        return {'packages':packages,'workspace_members':['0','1','2','3'],
                'resolve':{'nodes':[{'id':key,'dependencies':deps} for key,deps in [('0',['1']),('1',['2','4']),('2',[]),('3',['2']),('4',[])]]}}

    def test_binding_is_excluded_and_native_build_dependencies_remain(self):
        result = qualifier.native_metadata(self.fixture())
        self.assertEqual({p['name'] for p in result['packages']},{'peerwork-cli','peerwork-runtime','peerwork-core','external-build-helper'})
        self.assertEqual(set(result['workspace_members']),{'0','1','2'})

    def test_missing_dependency_or_reachable_binding_cannot_shrink_the_inventory(self):
        data = self.fixture();data['resolve']['nodes'][0]['dependencies'].append('missing')
        with self.assertRaisesRegex(AssertionError,'incomplete'):qualifier.native_metadata(data)
        data = self.fixture();data['resolve']['nodes'][0]['dependencies'].append('3')
        with self.assertRaisesRegex(AssertionError,'binding wrapper'):qualifier.native_metadata(data)


if __name__ == '__main__':
    unittest.main()
