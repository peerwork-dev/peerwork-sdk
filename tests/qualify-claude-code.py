#!/usr/bin/env python3
"""Exercise a real Claude Code MCP client without a login, service or model call.

Python is a test driver, not a Peerwork client dependency. Both executable paths
are explicit. All configuration and profiles are synthetic and temporary.
This does not qualify unsolicited model wake or a signed Peer round trip.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--claude', type=Path, required=True)
    parser.add_argument('--peerwork', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    claude, peerwork = args.claude.resolve(strict=True), args.peerwork.resolve(strict=True)
    assert not args.report.exists(), 'use a fresh qualification report'
    with tempfile.TemporaryDirectory(prefix='peerwork claude qualification ') as temporary:
        root = Path(temporary).resolve(strict=True)
        root.chmod(0o700)
        config = root / 'claude-config'
        config.mkdir(mode=0o700)
        profile = root / 'synthetic-profile.json'
        profile.write_text(json.dumps({
            'format': 'peerwork.agent-profile.v1',
            'endpoint_path': str(root / 'no-service-endpoint.json'),
            'expected_origin': 'https://example.invalid',
            'expected_actor': 'A' * 43,
            'scopes': {},
        }))
        profile.chmod(0o600)
        env = dict(os.environ, CLAUDE_CONFIG_DIR=str(config), PWD=str(root),
                   DISABLE_AUTOUPDATER='1', DISABLE_TELEMETRY='1',
                   DISABLE_ERROR_REPORTING='1', MCP_SDK_GENERATION='v2')
        env.pop('MCP_PROTOCOL_NEGOTIATION',None)
        trace=root/'handshake.jsonl'
        relay=Path(__file__).resolve().parent/'fixtures/claude-mcp-wire-proxy.py'

        def run(*words):
            result = subprocess.run([str(claude), *map(str, words)], cwd=root,
                                    env=env, text=True, capture_output=True, timeout=30)
            assert result.returncode == 0, 'Claude CLI failed; inspect isolated host diagnostics'
            return result.stdout

        version = run('--version').strip()
        registered = run('mcp', 'add', '--scope', 'local', '--transport', 'stdio',
                         'peerwork-qualification', '--', sys.executable,relay,trace,peerwork, 'agent',
                         '--profile', profile, 'mcp', '--claude-channel')
        assert 'peerwork-qualification' in registered
        health = run('mcp', 'list')
        line = next(line for line in health.splitlines()
                    if line.startswith('peerwork-qualification:'))
        assert 'Connected' in line and 'Failed' not in line, 'real MCP handshake did not connect'
        observations=[json.loads(line) for line in trace.read_text().splitlines()]
        negotiated=[row['negotiated'] for row in observations if row.get('negotiated')]
        assert negotiated and all(version!='2026-07-28' for version in negotiated)
        probes=[row for row in observations if row.get('method')=='server/discover']
        assert not probes or all(any(reply.get('direction')=='SERVER_TO_HOST' and reply.get('id')==probe['id'] and reply.get('error_code')==-32601 for reply in observations) for probe in probes)
        report = {
            'state': 'PASS', 'claude_version': version,
            'native_binary_sha256': hashlib.sha256(peerwork.read_bytes()).hexdigest(),
            'mcp_connection': 'CONNECTED', 'global_negotiation_override':False,
            'host_runtime':'v2','negotiated_versions':negotiated,'modern_probe_observed':bool(probes),
            'handshake_observations':observations, 'identity': 'SYNTHETIC_NO_SERVICE',
            'model_calls': 0, 'user_configuration_changed': False,
            'live_channel_model_round_trip': 'NOT_EXERCISED',
            'scope': 'real Claude CLI discovers the native Peerwork MCP server',
        }
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
