"""A 127.0.0.1 stand-in for a model endpoint, for the reader tests.

    with StubLLM(answers=["yes", "no"]) as stub:
        reader = OpenAICompatReader(base_url=stub.url + "/v1", model="m")
        ...
    stub.requests   # every request: {"path", "headers", "body"}

It speaks three shapes by path:
  .../chat/completions         OpenAI-compatible: choices[0].message.content
  .../messages                 Anthropic Messages: content[0].text
  ...:generateContent          Gemini: candidates[0].content.parts[0].text

`answers` is a list (cycled) or a callable(request_index, body) -> str. An
answer of StubLLM.FAIL makes that request answer HTTP 500; StubLLM.GARBLE
answers with bytes that are not JSON. Binds 127.0.0.1 on a free port only;
never touches any other host.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class StubLLM:
    FAIL = object()
    GARBLE = object()

    def __init__(self, answers=("yes",)):
        self.answers = answers
        self.requests = []
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    @property
    def url(self):
        assert self._server is not None, "StubLLM.url read outside its with block"
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def _answer_for(self, i, body):
        if callable(self.answers):
            return self.answers(i, body)
        return self.answers[i % len(self.answers)]

    def __enter__(self):
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                try:
                    body = json.loads(raw.decode("utf-8"))
                except ValueError:
                    body = None
                with stub._lock:
                    i = len(stub.requests)
                    stub.requests.append({"path": self.path,
                                          "headers": {k.lower(): v for k, v in self.headers.items()},
                                          "body": body})
                ans = stub._answer_for(i, body)
                if ans is StubLLM.FAIL:
                    self.send_response(500)
                    self.end_headers()
                    return
                if ans is StubLLM.GARBLE:
                    out = b"<html>not json</html>"
                else:
                    out = json.dumps(_shape(self.path, ans)).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        assert self._server is not None and self._thread is not None, "StubLLM exited without entering"
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        return False


def _shape(path, text):
    if path.endswith("/chat/completions"):
        return {"id": "stub", "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                             "finish_reason": "stop"}]}
    if path.endswith("/messages"):
        return {"id": "stub", "type": "message", "role": "assistant",
                "content": [{"type": "text", "text": text}], "stop_reason": "end_turn"}
    if ":generateContent" in path:
        return {"candidates": [{"content": {"role": "model", "parts": [{"text": text}]}}]}
    return {"error": f"stub does not speak {path}"}
