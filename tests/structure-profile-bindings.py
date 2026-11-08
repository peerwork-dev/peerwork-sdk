"""Binding transport test; cryptographic verification is tested in Rust core."""
import ast
import faulthandler
import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


class StructureBinding(unittest.TestCase):
    def test_submission_and_status_preserve_verified_data(self):
        path = Path(__file__).resolve().parents[1] / "bindings/python/peerwork/__init__.py"
        name = "peerwork_structure_binding_test"
        native = types.ModuleType(name + "._peerwork_native")
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom) and node.module == "_peerwork_native":
                for alias in node.names:
                    setattr(native, alias.name, lambda *args, **kwargs: None)
        class Cancel:
            def cancel(self):
                pass
        native.KernelCancelHandle = Cancel
        calls = []
        completed_mode = [False]
        structure = {"profile": "backend-structure-v1", "assurance": "BACKEND_CURRENT_STATE",
                     "workspace_id": "workspace", "state": {"holder": "agent"},
                     "sealed_content": {"ciphertext": "opaque"}}
        def dispatch(operation, *args):
            calls.append(operation)
            if operation == "pending_page":
                self.assertEqual(json.loads(args[6]), {"after": "cursor", "preparations_after": None, "limit": 1})
                return json.dumps({"items": [], "next_after": "next", "consistency": "LIVE_KEYSET"})
            if operation == "build_pending_index":
                return json.dumps({"complete": False, "scanned_rows": 2048})
            if operation == "ensure_local_content_key":
                self.assertEqual(json.loads(args[6]), {"workspace_id": "space"})
                return json.dumps({"workspace_id": "space", "key_id": "local-key"})
            accepted = {"command_id": "command", "structure_result_json": json.dumps(structure)}
            if completed_mode[0]:
                return json.dumps({"state": "COMPLETED", "command_id": "original-admission", "result": accepted})
            return json.dumps({"state": "ACCEPTED", "result": accepted} if operation in ("status", "execute_structure_intent", "resume_structure_intent") else accepted)
        native.kernel_json = dispatch
        sys.modules[native.__name__] = native
        spec = importlib.util.spec_from_file_location(name, path, submodule_search_locations=[str(path.parent)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
            client = module.KernelClient("https://example.invalid", "/selected/journal", "/selected/identity")
            result = client.submit_saved("command")
            self.assertEqual(result["structure"], structure)
            self.assertNotIn("structure_result_json", result)
            self.assertEqual(client.status("command")["result"]["structure"], structure)
            self.assertEqual(asyncio.run(client.submit_saved_async("command"))["structure"], structure)
            intent = {"action": "structure.workspace.create", "idempotency_key": "create-once", "body": {"name": "test"}}
            self.assertEqual(client.execute_structure_intent(intent)["result"]["structure"], structure)
            self.assertEqual(client.resume_structure_intent("command")["result"]["structure"], structure)
            self.assertEqual(asyncio.run(client.execute_structure_intent_async(intent))["result"]["structure"], structure)
            self.assertEqual(asyncio.run(client.resume_structure_intent_async("command"))["result"]["structure"], structure)
            self.assertEqual(calls, ["submit_saved", "status", "submit_saved", "execute_structure_intent", "resume_structure_intent", "execute_structure_intent", "resume_structure_intent"])
            self.assertEqual(client.pending_page(after="cursor", limit=1)["next_after"], "next")
            self.assertEqual(asyncio.run(client.pending_page_async(after="cursor", limit=1))["next_after"], "next")
            self.assertFalse(client.build_pending_index()["complete"])
            self.assertEqual(asyncio.run(client.build_pending_index_async())["scanned_rows"], 2048)
            self.assertEqual(client.ensure_local_content_key("space")["key_id"], "local-key")
            self.assertEqual(asyncio.run(client.ensure_local_content_key_async("space"))["key_id"], "local-key")
            completed_mode[0] = True
            completed = client.execute_structure_intent({"action": "structure.maintenance.rebuild", "body": {}})
            self.assertEqual(completed["state"], "COMPLETED")
            self.assertEqual(completed["command_id"], "original-admission")
            self.assertEqual(completed["result"]["command_id"], "command")
            self.assertEqual(completed["result"]["structure"], structure)
            completed_mode[0] = False
            context_calls = []
            def context_dispatch(operation, profile, actor, service, wire, cancel):
                context_calls.append((operation, None if wire is None else json.loads(wire)))
                return json.dumps({"ok": True, "value": {"context": {"schema": "peerwork.agent-context.v2", "fingerprint": "selected", "actor_id": actor}, "status": "ready"}})
            module.agent_context_json = context_dispatch
            ctx = module.bind_structure_context(profile="/selected/context", expected_actor="worker", expected_service="service",
                origin="https://example.invalid", identity_path="/selected/identity", journal_path="/selected/journal", workspace_ids=["space"])
            ctx.discover("space", limit=1)
            ctx.describe("space", "instance", protocol_digest="digest")
            ctx.execute_structure_intent("space", {"action": "structure.events.read", "body": {}})
            asyncio.run(ctx.execute_structure_intent_async("space", {"action": "structure.events.read", "body": {}}))
            ctx.recover("space", operation_id="same-operation")
            ctx.operations("space", scope="WORKSPACE", view="HISTORY", limit=1)
            ctx.follow_operation("space", {"job_id": "job", "instance_id": "instance", "protocol_digest": "digest"})
            asyncio.run(ctx.follow_operation_async("space", {"job_id": "job", "instance_id": "instance", "protocol_digest": "digest"}))
            self.assertEqual([c[0] for c in context_calls], ["bind.structure", "open", "discover", "describe", "execute.structure", "execute.structure", "recover", "operations", "follow.operation", "follow.operation"])
            self.assertEqual(context_calls[0][1]["execution_profile"], "backend-structure-v1")
            self.assertFalse(context_calls[0][1]["allow_loopback_http"])
            self.assertEqual(context_calls[3][1]["query"]["protocol_digest"], "digest")
            for _, request in context_calls[2:]:
                self.assertEqual(request["expected_fingerprint"], "selected")
        finally:
            sys.modules.pop(name, None)
            sys.modules.pop(native.__name__, None)


if __name__ == "__main__":
    faulthandler.dump_traceback_later(10, exit=True)
    unittest.main()
