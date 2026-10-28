"""Pinned protocol interaction, without a model loop or host-session delivery."""
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import re
from urllib.parse import urlsplit, urlunsplit


class ProtocolSessionError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _fail(code):
    raise ProtocolSessionError(code)


def _snapshot(value):
    return json.loads(json.dumps(value, ensure_ascii=True, allow_nan=False))


def _token(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is not None


def _integer(value):
    return type(value) is int and abs(value) <= 9007199254740991


def _origin(value):
    if not isinstance(value, str):
        _fail("PROTOCOL_BINDING_INVALID")
    try:
        u = urlsplit(value)
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment:
            _fail("PROTOCOL_BINDING_INVALID")
        host = u.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        port = u.port
        if port is not None and port != (443 if u.scheme == "https" else 80):
            host += ":" + str(port)
        return urlunsplit((u.scheme, host, u.path, "", "")).removesuffix("/")
    except ValueError:
        _fail("PROTOCOL_BINDING_INVALID")


def _accepted(out):
    return out.get("state") in ("ACCEPTED", "COMPLETED")


class ProtocolSession:
    """Native Kernel owns verification, encryption and durable operation recovery.

    A session here is a pinned protocol selection, not a model conversation.
    """
    _KEYS = {"expected_origin", "expected_actor", "workspace_id", "instance_id", "protocol_digest", "package_digest", "role"}

    def __init__(self, kernel, binding: dict):
        from . import ProtocolClient
        self.kernel = kernel
        self._binding = _snapshot(binding)
        b = self._binding
        if not isinstance(b, dict) or set(b) != self._KEYS or not all(_token(b[k]) for k in ("expected_actor", "workspace_id", "instance_id", "role")) or not all(isinstance(b[k], str) and re.fullmatch(r"[a-f0-9]{64}", b[k]) for k in ("protocol_digest", "package_digest")):
            _fail("PROTOCOL_BINDING_INVALID")
        opened = kernel.open()
        if opened["actor_id"] != b["expected_actor"] or _origin(opened["origin"]) != _origin(b["expected_origin"]):
            _fail("PROTOCOL_BINDING_MISMATCH")
        self._scope = {k: b[k] for k in ("workspace_id", "instance_id", "protocol_digest")}
        self._protocols = ProtocolClient(kernel)
        self._tools = None
        self._kernel_config = self._config()

    def _config(self):
        return copy.deepcopy({k: getattr(self.kernel, k, None) for k in ("origin", "journal_path", "identity_path", "authority", "required_features", "allow_loopback_http", "transport")})

    def _assert_kernel(self):
        if self._config() != self._kernel_config:
            _fail("PROTOCOL_BINDING_MISMATCH")

    @property
    def binding(self):
        return copy.deepcopy(self._binding)

    def _check_result(self, out):
        if _accepted(out) and any(out["result"].get(k) != v for k, v in self._scope.items()):
            _fail("PROTOCOL_BINDING_MISMATCH")
        return out

    def _read(self, action, body):
        self._assert_kernel()
        return self._check_result(self.kernel.execute_structure_intent({"action": action, **self._scope, "body": body}))

    def describe(self):
        self._assert_kernel()
        self._tools = None
        b = self._binding
        out = self._protocols.role(b["workspace_id"], b["instance_id"], b["role"])
        if not _accepted(out):
            return {"outcome": out, "context": None}
        v = out["result"]["structure"]
        if any(v.get(k) != b[k] for k in ("workspace_id", "protocol_digest", "package_digest")) or v.get("runtime", {}).get("actor_id") != b["expected_actor"] or v.get("runtime", {}).get("role") != b["role"] or v.get("evidence", {}).get("binding", {}).get("instance_id") != b["instance_id"]:
            _fail("PROTOCOL_BINDING_MISMATCH")
        runtime = v["runtime"]
        resource = v.get("resources", {}).get(runtime.get("instructions_resource"), {})
        if not isinstance(resource.get("content"), str) or not isinstance(runtime.get("tools"), list):
            _fail("PROTOCOL_CONTEXT_INVALID")
        self._tools = copy.deepcopy(runtime["tools"])
        return {"outcome": out, "context": {"binding": self.binding, "instructions": resource["content"], "tools": copy.deepcopy(self._tools), "context_sources": runtime["context"], "assurance": "BACKEND_CURRENT_STATE"}}

    @staticmethod
    def _page(query, events=False):
        q = _snapshot(query)
        allowed = {"limit", "cursor", "after_sequence"} if events else {"limit", "cursor", "schema", "consistency"}
        if set(q) - allowed or not _integer(q.get("limit", 16)) or not 1 <= q.get("limit", 16) <= 32:
            _fail("PROTOCOL_PAGE_INVALID")
        if "cursor" in q and (not isinstance(q["cursor"], str) or not q["cursor"] or len(q["cursor"]) > 16384):
            _fail("PROTOCOL_PAGE_INVALID")
        if "after_sequence" in q and (not _integer(q["after_sequence"]) or q["after_sequence"] < 0 or "cursor" in q):
            _fail("PROTOCOL_PAGE_INVALID")
        return {**q, "limit": q.get("limit", 16)}

    def state(self):
        return self._read("structure.instance.get", {})

    def records(self, **query):
        return self._read("structure.records.read", self._page(query))

    def updates(self, **query):
        return self._read("structure.events.read", self._page(query, events=True))

    def record(self, reference: dict):
        r = _snapshot(reference)
        if set(r) != {"record_id", "revision"} or not _token(r["record_id"]) or not _integer(r["revision"]) or r["revision"] < 1:
            _fail("PROTOCOL_REFERENCE_INVALID")
        return self._read("structure.record.get", r)

    def prepare_action(self, request: dict):
        self._assert_kernel()
        if self._tools is None:
            _fail("PROTOCOL_CONTEXT_REQUIRED")
        r = _snapshot(request)
        if set(r) - {"tool", "action_id", "values", "expected_revision", "operation_id", "plaintext_contents"} or bool(r.get("tool")) == bool(r.get("action_id")) or not _integer(r.get("expected_revision")) or r["expected_revision"] < 1 or not isinstance(r.get("operation_id"), str) or not 1 <= len(r["operation_id"].encode("utf-16-le")) // 2 <= 128 or not isinstance(r.get("values"), dict):
            _fail("PROTOCOL_ACTION_INVALID")
        tool = next((t for t in self._tools if t.get("name") == r["tool"]), None) if r.get("tool") else next((t for t in self._tools if t.get("action") == r["action_id"]), None)
        if tool is None:
            _fail("PROTOCOL_ACTION_NOT_GRANTED")
        refs = []
        for name, field in (tool.get("input_schema") or {}).get("fields", {}).items():
            if field.get("type") != "exact_ref" or name not in r["values"]:
                continue
            value = r["values"][name]
            if not isinstance(value, dict) or set(value) != {"record_id", "revision"} or not _token(value["record_id"]) or not _integer(value["revision"]) or value["revision"] < 1:
                _fail("PROTOCOL_REFERENCE_INVALID")
            if value not in refs:
                refs.append(value)
        intent = {"action": "structure.action", **self._scope, "expected_instance_revision": r["expected_revision"], "idempotency_key": r["operation_id"], "exact_input_refs": refs, "body": {"action_id": tool["action"], "structure": r["values"]}}
        if "plaintext_contents" in r:
            intent["plaintext_contents"] = r["plaintext_contents"]
        return {"format": "peerwork.protocol-action.v1", "binding": self.binding, "intent": intent}

    def submit(self, prepared: dict):
        self._assert_kernel()
        p = _snapshot(prepared)
        i = p.get("intent", {})
        if set(p) != {"format", "binding", "intent"} or p["format"] != "peerwork.protocol-action.v1" or p["binding"] != self._binding or i.get("action") != "structure.action" or any(i.get(k) != v for k, v in self._scope.items()) or set(i) - {"action", *self._scope, "expected_instance_revision", "idempotency_key", "exact_input_refs", "body", "plaintext_contents"} or not isinstance(i.get("idempotency_key"), str) or not 1 <= len(i["idempotency_key"].encode("utf-16-le")) // 2 <= 128 or not _integer(i.get("expected_instance_revision")) or i["expected_instance_revision"] < 1:
            _fail("PROTOCOL_BINDING_MISMATCH")
        return self._check_result(self.kernel.execute_structure_intent(i))

    def resume(self, prepared: dict):
        """Recover the exact prepared intent, retaining its original CAS and ID."""
        return self.submit(prepared)

    def action(self, request: dict):
        return self.submit(self.prepare_action(request))
