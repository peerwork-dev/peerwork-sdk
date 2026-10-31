#!/usr/bin/env python3
"""Synthetic qualification-only byte-transparent MCP timing observer.

No client runtime dependency. Trace fixed method/tool labels and monotonic
times, never arguments, results, raw request IDs or stderr. Forwarded stdout is
not proof that a harness consumed input or started a model turn.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import threading
import time

METHODS = {'initialize', 'tools/list', 'tools/call', 'ping', 'notifications/initialized', 'notifications/cancelled'}
TOOLS = {'peerwork_' + name for name in ('context', 'protocol', 'act', 'read', 'send', 'reply', 'inbox', 'consume', 'status', 'receipts', 'recover', 'wait')}


class Trace:
    def __init__(self, path):
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.lock = threading.Lock()
        self.pending = {}
        self.index = self.events = 0
        self.truncated = False

    def emit(self, value):
        if self.events >= 512:
            if self.truncated:
                return
            self.truncated = True
            value = {'event': 'TRUNCATED'}
        value['monotonic_ns'] = time.monotonic_ns()
        os.write(self.fd, (json.dumps(value, separators=(',', ':')) + '\n').encode())
        self.events += 1

    def frame(self, data, response):
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            return
        if not isinstance(value, dict):
            return
        request_id = value.get('id')
        if type(request_id) not in (int, str) or len(str(request_id)) > 256:
            return
        key = (type(request_id), request_id)
        with self.lock:
            if response:
                selected = self.pending.pop(key, None)
                if selected is not None:
                    self.emit({'event': 'RESPONSE_READ', 'index': selected,
                               'rpc_error': 'error' in value})
            elif 'method' in value:
                if key in self.pending:
                    self.emit({'event': 'DUPLICATE_ID'})
                    return
                self.index += 1
                if len(self.pending) >= 64:
                    self.emit({'event': 'PENDING_LIMIT'})
                    return
                self.pending[key] = self.index
                method = value['method'] if isinstance(value['method'], str) and value['method'] in METHODS else 'OTHER'
                params = value.get('params')
                name = params.get('name') if isinstance(params, dict) else None
                self.emit({'event': 'REQUEST_READ', 'index': self.index, 'method': method,
                           'tool': name if isinstance(name, str) and name in TOOLS else None})

    def copy(self, source, target, response):
        pending = bytearray()
        oversized = False
        while data := os.read(source, 65536):
            # Observe complete JSONL frames before forwarding their final bytes.
            # Oversized diagnostic frames are ignored, never modified/dropped.
            for part in data.splitlines(keepends=True):
                if not oversized:
                    pending.extend(part)
                    if len(pending) > 32 * 1024 * 1024 + 1:
                        pending.clear()
                        oversized = True
                if part.endswith(b'\n'):
                    if not oversized:
                        self.frame(pending, response)
                    pending.clear()
                    oversized = False
            view = memoryview(data)
            while view:
                count = os.write(target, view)
                if not count:
                    raise BrokenPipeError
                view = view[count:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--trace', type=Path, help='One fresh trace file for a single MCP process')
    target.add_argument('--trace-dir', type=Path,
                        help='Private directory; create a distinct trace for each MCP process/restart')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('native MCP command required')
    path = args.trace
    if args.trace_dir is not None:
        args.trace_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        meta = args.trace_dir.lstat()
        if not stat.S_ISDIR(meta.st_mode) or (os.name != 'nt' and
                (meta.st_uid != os.geteuid() or meta.st_mode & 0o077)):
            parser.error('private trace directory required')
        path = args.trace_dir / f'mcp-{os.getpid()}-{os.urandom(8).hex()}.jsonl'
    trace = Trace(path)
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def pump(source, target, response):
        try:
            trace.copy(source, target, response)
        except (OSError, ValueError):
            if child.poll() is None:
                child.terminate()
        finally:
            if not response:
                child.stdin.close()

    writer = threading.Thread(target=pump, args=(0, child.stdin.fileno(), False), daemon=True)
    reader = threading.Thread(target=pump, args=(child.stdout.fileno(), 1, True), daemon=True)
    writer.start()
    reader.start()
    result = child.wait()
    reader.join(timeout=5)
    # A host may leave stdin open after its MCP child exits. The daemon reader
    # never owns Python's buffered stdio locks and cannot stall process exit.
    with trace.lock:
        trace.emit({'event': 'CHILD_EXIT', 'exit_code': result,
                    'pending': len(trace.pending), 'truncated': trace.truncated})
    return result


if __name__ == '__main__':
    raise SystemExit(main())
