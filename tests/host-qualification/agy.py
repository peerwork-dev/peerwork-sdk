"""Prepare a real AGY ACP session using a deterministic loopback Gemini model."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import queue
import subprocess
import threading
from urllib.parse import urlsplit


class Completion(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, result, stream=False):
        body = json.dumps(result).encode()
        if stream:
            body = b"data: " + body + b"\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if stream else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.respond({"models": [{"name": "models/gemini-3.5-flash",
                                  "supportedGenerationMethods": ["generateContent"]}]})

    def do_POST(self):
        try:
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            path = urlsplit(self.path).path
            if path.endswith(":countTokens"):
                self.respond({"totalTokens": 10})
                return
            if not path.endswith((":generateContent", ":streamGenerateContent")):
                self.send_error(404)
                return
            call, text = self.server.fixture.complete(self.chat_request(request))
            part = {"text": text} if call is None else {"functionCall": {
                "name": call["function"]["name"], "args": json.loads(call["function"]["arguments"]),
            }}
            self.respond({
                "candidates": [{"content": {"role": "model", "parts": [part]},
                                "finishReason": "STOP", "index": 0}],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 10,
                                  "totalTokenCount": 20},
                "modelVersion": "gemini-3.5-flash",
            }, stream=path.endswith(":streamGenerateContent"))
        except (AssertionError, KeyError, ValueError) as error:
            (self.server.fixture.output / "model-error.txt").write_text(str(error))
            self.send_error(500, "SYNTHETIC_MODEL_FIXTURE_ERROR")

    @staticmethod
    def chat_request(request):
        tools = [{"function": declaration} for tool in request.get("tools", [])
                 for declaration in tool.get("functionDeclarations", [])]
        messages = []
        pending = {}
        for content in request["contents"]:
            for part in content.get("parts", []):
                if "functionCall" in part:
                    name = part["functionCall"]["name"]
                    call_id = f"agy-{len(messages)}"
                    pending[name] = call_id
                    messages.append({"role": "assistant", "tool_calls": [
                        {"id": call_id, "function": {"name": name}},
                    ]})
                elif "functionResponse" in part:
                    response = part["functionResponse"]
                    messages.append({"role": "tool", "tool_call_id": pending[response["name"]],
                                     "content": json.dumps(response["response"])})
                elif "text" in part:
                    messages.append({"role": "assistant" if content["role"] == "model" else "user",
                                     "content": part["text"]})
        return {"messages": messages, "tools": tools}


def bootstrap(executable, project, env, root):
    """Create the fixture conversation through ACP and release its process."""
    with (root / "agy-bootstrap.log").open("w") as log:
        process = subprocess.Popen(
            [executable, "acp", "--disable-telemetry"], cwd=project, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True,
        )
        frames = queue.Queue()

        def read_frames():
            for line in process.stdout:
                frames.put(line)
            frames.put(None)

        threading.Thread(target=read_frames, daemon=True).start()

        def request(id, method, params):
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": id, "method": method,
                                            "params": params}) + "\n")
            process.stdin.flush()
            for _ in range(40):
                frame = frames.get(timeout=20)
                if frame is None:
                    raise RuntimeError("AGY_ACP_BOOTSTRAP_EXITED")
                value = json.loads(frame)
                if value.get("id") == id and "method" not in value:
                    return value
            raise RuntimeError("AGY_ACP_BOOTSTRAP_RESPONSE_MISSING")

        try:
            initialized = request(1, "initialize", {"protocolVersion": 1, "clientCapabilities": {},
                "clientInfo": {"name": "peerwork-host-qualification", "version": "1"}})
            if initialized.get("result", {}).get("protocolVersion") != 1:
                raise RuntimeError("AGY_ACP_INITIALIZATION_FAILED")
            selection = {"cwd": str(project), "mcpServers": []}
            selected = request(2, "session/new", selection)
            if selected.get("error", {}).get("code") == -32000:
                auth = request(3, "authenticate", {"methodId": "gemini-api-key"})
                if "error" in auth:
                    raise RuntimeError("AGY_ACP_FIXTURE_AUTHENTICATION_FAILED")
                selected = request(4, "session/new", selection)
            conversation = selected.get("result", {}).get("sessionId")
            if not isinstance(conversation, str):
                raise RuntimeError("AGY_ACP_FIXTURE_CONVERSATION_UNAVAILABLE")
            return conversation
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=8)


def prepare(executable, root, env, stack, model):
    project = root / "agy-project"
    project.mkdir()
    settings = Path(env["HOME"]) / ".gemini/antigravity-cli/settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"modelProvider":"gemini"}\n')
    gateway = ThreadingHTTPServer(("127.0.0.1", 0), Completion)
    gateway.fixture = model
    stack.callback(gateway.server_close)
    threading.Thread(target=gateway.serve_forever, daemon=True).start()
    stack.callback(gateway.shutdown)
    env.update(GEMINI_API_KEY="synthetic-no-paid-provider",
               GOOGLE_GEMINI_BASE_URL=f"http://127.0.0.1:{gateway.server_port}")
    conversation = bootstrap(executable, project, env, root)
    env.update(PEERWORK_TEST_AGY_PROJECT=str(project), PEERWORK_TEST_AGY_EXECUTABLE=str(executable),
               PEERWORK_TEST_AGY_CONVERSATION=conversation)
