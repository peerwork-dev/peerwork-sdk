"""Synthetic observer privacy, bounds and unchanged MCP byte forwarding."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROXY = Path(__file__).with_name('mcp-timing-proxy.py')
spec = importlib.util.spec_from_file_location('mcp_timing', PROXY)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TimingProxyTests(unittest.TestCase):
    def test_restarted_mcp_processes_get_distinct_private_traces(self):
        with tempfile.TemporaryDirectory() as directory:
            traces = Path(directory) / 'timing'
            request = (json.dumps({'jsonrpc': '2.0', 'id': 'private-id', 'method': 'tools/call',
                'params': {'name': 'peerwork_reply', 'arguments': {'text': 'private-body'}}}) + '\n').encode()
            for _ in range(2):
                result = subprocess.run([sys.executable, str(PROXY), '--trace-dir', str(traces), '--',
                    sys.executable, '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                    input=request, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, request)
            files = list(traces.glob('*.jsonl'))
            self.assertEqual(len(files), 2)
            for path in files:
                raw = path.read_text()
                self.assertNotIn('private-', raw)
                records = [json.loads(line) for line in raw.splitlines()]
                self.assertEqual([r['index'] for r in records if r['event'] == 'REQUEST_READ'], [1])
                self.assertEqual(records[-1]['event'], 'CHILD_EXIT')
                self.assertEqual(records[-1]['pending'], 0)
                if os.name != 'nt':
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_out_of_order_results_are_unchanged_and_private_fields_are_not_traced(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / 'timing.jsonl'
            requests = [{'jsonrpc': '2.0', 'id': secret, 'method': 'tools/call',
                         'params': {'name': 'peerwork_reply', 'arguments': {'text': secret}}}
                        for secret in ('private-first-id-and-body', 'private-second-id-and-body')]
            script = '''import sys,json
requests=[json.loads(sys.stdin.buffer.readline()) for _ in range(2)]
for r in reversed(requests):
 data=(json.dumps({'id':r['id'],'result':r['params']['arguments']})+'\\n').encode()
 for start in range(0,len(data),7):sys.stdout.buffer.write(data[start:start+7]);sys.stdout.buffer.flush()
'''
            expected = b''.join((json.dumps({'id':r['id'],'result':r['params']['arguments']})+'\n').encode() for r in reversed(requests))
            result = subprocess.run([sys.executable, str(PROXY), '--trace', str(trace), '--', sys.executable, '-c', script],
                                    input=b''.join((json.dumps(r)+'\n').encode() for r in requests), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
            raw = trace.read_text()
            self.assertNotIn('private-', raw)
            rows = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual([r['index'] for r in rows if r['event'] == 'RESPONSE_READ'], [2, 1])
            self.assertEqual(rows[-1]['pending'], 0)
            if os.name != 'nt':
                self.assertEqual(trace.stat().st_mode & 0o777, 0o600)

    def test_trace_bounds_duplicate_ids_and_unknown_methods_do_not_export_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace'
            trace = module.Trace(path)
            try:
                trace.frame(json.dumps({'id': 1, 'method': {'private': 'secret'}}), False)
                trace.frame(json.dumps({'id': 1, 'method': 'private-secret'}), False)
                for i in range(2, 1000):
                    trace.frame(json.dumps({'id': i, 'method': 'private-secret'}), False)
                self.assertEqual(len(trace.pending), 64)
            finally:
                os.close(trace.fd)
            raw = path.read_text()
            self.assertNotIn('secret', raw)
            rows = [json.loads(line) for line in raw.splitlines()]
            self.assertLessEqual(len(rows), 513)
            self.assertTrue(any(r['event'] == 'DUPLICATE_ID' for r in rows))
            self.assertEqual(rows[-1]['event'], 'TRUNCATED')


if __name__ == '__main__':
    unittest.main()
