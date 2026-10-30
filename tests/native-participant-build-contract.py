"""Candidate source-inventory scope, without building an artifact or using a secret."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('qualify_participant',Path(__file__).resolve().parents[1] / 'tools/release/qualify-participant.py')
qualifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualifier)


class NativeGraphTests(unittest.TestCase):
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
