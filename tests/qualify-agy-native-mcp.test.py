#!/usr/bin/env python3
"""Keep legitimate lazy discovery distinct from forbidden source/tool access."""
import importlib.util
from pathlib import Path
import unittest
import json
import tempfile
spec=importlib.util.spec_from_file_location('qualify',Path(__file__).with_name('qualify-agy-native-mcp.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class ResourceReads(unittest.TestCase):
    skill=Path('/tmp/test/.agents/skills/peerwork/SKILL.md')
    schema=Path('/root/.gemini/antigravity-cli/mcp/unique-test-server')
    methods=['inbox','reply']
    def classify(self,path,name='read_file',**extra):
        return module.classify_resource_read(name,dict(AbsolutePath=path,**extra),self.skill,self.schema,self.methods)
    def test_supplied_skill(self):
        self.assertEqual(self.classify(str(self.skill)),'PEERWORK_SKILL')
    def test_exact_schema(self):
        self.assertEqual(self.classify(str(self.schema/'peerwork_reply.json')),'AGY_MCP_TOOL_DESCRIPTOR')
    def test_source_is_not_a_resource(self):
        self.assertIsNone(self.classify('/sdk/crates/runtime/src/agent_mcp.rs'))
    def test_other_server_is_not_a_resource(self):
        self.assertIsNone(self.classify(str(self.schema.parent/'other/peerwork_reply.json')))
    def test_unknown_schema_is_not_a_resource(self):
        self.assertIsNone(self.classify(str(self.schema/'admin.json')))
    def test_traversal_is_not_a_resource(self):
        self.assertIsNone(self.classify(str(self.schema/'../unique-test-server/peerwork_reply.json')))
    def test_ambiguous_arguments_and_wrong_tool(self):
        self.assertIsNone(self.classify(str(self.skill),file_path='/sdk/private.rs'))
        self.assertIsNone(self.classify(str(self.skill),name='run_command'))


class TransportObservation(unittest.TestCase):
    def test_restart_request_ids_are_paired_only_with_their_own_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, start, end in [('one', 100, 200), ('two', 1000, 5000)]:
                records = [dict(event='REQUEST_READ', index=1, method='tools/call', tool='peerwork_reply', monotonic_ns=start),
                           dict(event='RESPONSE_READ', index=1, rpc_error=False, monotonic_ns=end),
                           dict(event='CHILD_EXIT', exit_code=0, pending=0)]
                (root / (name + '.jsonl')).write_text('\n'.join(json.dumps(r) for r in records))
            result = module.observe_mcp_transport(root)
            self.assertTrue(result['complete'])
            self.assertEqual([call['duration_ms'] for call in result['calls']], [0.0001, 0.004])

    def test_missing_or_corrupt_measurement_is_not_a_complete_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertFalse(module.observe_mcp_transport(root)['complete'])
            (root / 'broken.jsonl').write_text('{')
            self.assertFalse(module.observe_mcp_transport(root)['complete'])
if __name__=='__main__':unittest.main()
