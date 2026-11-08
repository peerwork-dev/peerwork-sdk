"""Task-local HTTP barrier for the installed multipart orphan recovery test.

The second POST after arming is held before it reaches the reference service.
Only its method, path and body SHA-256 are retained. A later POST must match
those bytes before forwarding. This observes transport, not SDK private state.
"""

import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Event, Lock
from urllib.parse import urlsplit


class Barrier:
    def __init__(self, upstream: str):
        parsed = urlsplit(upstream)
        assert parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")
        self.upstream_host = parsed.hostname
        self.upstream_port = parsed.port
        self.lock = Lock()
        self.release = Event()
        self.armed = False
        self.post_count = 0
        self.held = None
        self.compare_next = False
        self.compared = False

    def snapshot(self):
        with self.lock:
            return {"post_count": self.post_count, "held": self.held is not None,
                    "held_request_sha256": self.held[2] if self.held else None,
                    "compared": self.compared}

    def control(self, command: str):
        with self.lock:
            if command == "arm":
                assert not self.armed and self.held is None
                self.armed = True
                self.post_count = 0
            elif command == "discard":
                assert self.held is not None
                self.armed = False
                self.release.set()
            elif command == "compare":
                assert self.held is not None and self.release.is_set()
                self.compare_next = True
            else:
                raise ValueError("unknown barrier command")
        return self.snapshot()

    def before_forward(self, method: str, path: str, body: bytes):
        fingerprint = (method, path, hashlib.sha256(body).hexdigest())
        is_commit_post = method == "POST" and path.startswith(
            "/api/workspace/v1/secure/workspaces/") and path.endswith("/commits")
        hold = False
        with self.lock:
            if is_commit_post and self.armed:
                self.post_count += 1
                if self.post_count == 2:
                    self.held = fingerprint
                    hold = True
            elif is_commit_post and self.compare_next:
                self.compare_next = False
                self.compared = fingerprint == self.held
                if not self.compared:
                    return False
        if hold:
            assert self.release.wait(120), "held request was never released"
            return False  # The original transport is discarded, never applied.
        return True


def start_barrier(upstream: str):
    state = Barrier(upstream)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return  # Never print request or response bodies.

        def _respond(self, status: int, body: bytes, headers=()):
            self.send_response(status)
            forwarded = set()
            for key, value in headers:
                if key.lower() not in ("connection", "content-length", "transfer-encoding"):
                    self.send_header(key, value)
                    forwarded.add(key.lower())
            if "content-type" not in forwarded:
                self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # The original caller was deliberately terminated at the barrier.

        def _handle(self):
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            if self.path == "/__proxy/status" and self.command == "GET":
                self._respond(200, json.dumps(state.snapshot()).encode())
                return
            if self.path.startswith("/__proxy/") and self.command == "POST":
                try:
                    result = state.control(self.path.removeprefix("/__proxy/"))
                    self._respond(200, json.dumps(result).encode())
                except (AssertionError, ValueError):
                    self._respond(409, b'{"error":"invalid barrier transition"}')
                return
            if not state.before_forward(self.command, self.path, body):
                self._respond(503, b'{"error":"test transport withheld"}')
                return
            upstream = HTTPConnection(state.upstream_host, state.upstream_port, timeout=120)
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in ("host", "connection", "content-length")}
            headers["Host"] = f"{state.upstream_host}:{state.upstream_port}"
            try:
                upstream.request(self.command, self.path, body=body, headers=headers)
                response = upstream.getresponse()
                payload = response.read()
                self._respond(response.status, payload, response.getheaders())
            finally:
                upstream.close()

        do_GET = _handle
        do_POST = _handle

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    return server, f"http://127.0.0.1:{server.server_port}/"
