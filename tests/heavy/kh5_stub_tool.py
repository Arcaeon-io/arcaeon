"""KH5 fixture: the loopback stub tool every surface forwards to.

One answer function, two transports, so the stdio child and the HTTP upstream
cannot disagree about what a tool says:

    python kh5_stub_tool.py RECEIVED_LOG     # stdio: one JSON-RPC frame per line

`HttpStub` is the same tool on 127.0.0.1, started and stopped by the test.
Both write the name of every tools/call they actually received, one per line,
to RECEIVED_LOG (stdio) or `HttpStub.received` (HTTP). That list is the proof
of what reached the tool: an enforce-mode block must never appear in it.
"""
from __future__ import annotations

import json
import sys


def answer(msg: dict) -> dict | None:
    """The tool's reply to one JSON-RPC message, or None for a notification."""
    if not isinstance(msg, dict) or msg.get("id") is None:
        return None
    if msg.get("method") != "tools/call":
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {}}
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    name = params.get("name")
    return {"jsonrpc": "2.0", "id": msg["id"], "result": {
        "content": [{"type": "text", "text": f"ran {name}"}]}}


def tool_name(msg) -> str | None:
    if isinstance(msg, dict) and msg.get("method") == "tools/call":
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        name = params.get("name")
        return name if isinstance(name, str) else "?"
    return None


class HttpStub:
    """The stub tool as a loopback HTTP JSON-RPC endpoint (POST /mcp)."""

    def __init__(self):
        import http.server
        import threading

        received = self.received = []
        lock = threading.Lock()

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with lock:
                    name = tool_name(msg)
                    if name is not None:
                        received.append(name)
                body = json.dumps(answer(msg)).encode()
                self.send_response_only(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.url = self.base + "/mcp"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._t.join(timeout=10)


def main(argv: list[str]) -> int:
    log = open(argv[1], "a", encoding="utf-8", newline="\n")
    out = sys.stdout.buffer
    try:
        for raw in sys.stdin.buffer:
            try:
                msg = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            name = tool_name(msg)
            if name is not None:
                log.write(name + "\n")
                log.flush()
            reply = answer(msg)
            if reply is not None:
                out.write(json.dumps(reply).encode() + b"\n")
                out.flush()
    finally:
        log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
