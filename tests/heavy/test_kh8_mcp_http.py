"""KH8: MCP over streamable HTTP, local.

`arcaeon mcp --http --port 0` is started as a real subprocess; the test reads
the bound port off its listening line, then does a real MCP initialize and
tools/list over HTTP with the serve token, and checks:

- the tool list over HTTP equals the list a real stdio `arcaeon mcp`
  subprocess hands back (name, description and input schema, tool for tool)
- a request without the token, or with a wrong one, is refused (401)
- a request whose Host header names anything but loopback is refused (400,
  the sentence `arcaeon serve` sends), and the listening line says 127.0.0.1
- every process started here is stopped

Without the [mcp] extra the HTTP tests skip with a reason. The fail-closed
test always runs: with the SDK made unimportable in the child, `--http`
prints COULD NOT LOOK naming the extra and exits 3. No network beyond
127.0.0.1.
"""
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"

try:
    import mcp  # noqa: F401
    import starlette  # noqa: F401
    import uvicorn  # noqa: F401
    HAVE_EXTRA = True
except ImportError:
    HAVE_EXTRA = False

needs_extra = pytest.mark.skipif(
    not HAVE_EXTRA, reason="the [mcp] extra (mcp, uvicorn, starlette) is not installed here")

ACCEPT = "application/json, text/event-stream"
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "kh8-test", "version": "1"}}}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


def _env(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["ARCAEON_HOME"] = str(tmp_path / "home")
    env["ARCAEON_JOURNAL"] = "0"
    env["ARCAEON_CALL_RECORD"] = str(tmp_path / "calls.jsonl")
    env["ARCAEON_LEDGER_LOG"] = str(tmp_path / "agent.log.jsonl")
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("ARCAEON_KEY", None)
    return env


def _lines(stream, q):
    for line in iter(stream.readline, ""):
        q.put(line)
    q.put(None)


def _stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
    for s in (proc.stdin, proc.stdout, proc.stderr):
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


@pytest.fixture()
def http_server(tmp_path):
    env = _env(tmp_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "arcaeon", "mcp", "--http", "--port", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        text=True, encoding="utf-8", env=env, cwd=str(tmp_path))
    q = queue.Queue()
    threading.Thread(target=_lines, args=(proc.stdout, q), daemon=True).start()
    try:
        line, deadline = "", time.monotonic() + 60
        while "listening on" not in line:
            left = deadline - time.monotonic()
            if left <= 0 or proc.poll() is not None:
                pytest.fail(f"arcaeon mcp --http did not print its listening line "
                            f"(exit {proc.poll()})")
            try:
                line = q.get(timeout=left) or ""
            except queue.Empty:
                continue
        m = re.search(r"http://(127\.0\.0\.1):(\d+)/mcp", line)
        assert m, line
        token = (tmp_path / "home" / "serve.token").read_text(encoding="utf-8").strip()
        yield {"proc": proc, "line": line, "host": m.group(1), "port": int(m.group(2)),
               "token": token}
    finally:
        _stop(proc)
    assert proc.poll() is not None, "the HTTP server is still running after the test"


def _post(port, body, token=None, host=None):
    headers = {"Content-Type": "application/json", "Accept": ACCEPT}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if host is not None:
        headers["Host"] = host
    req = urllib.request.Request(f"http://127.0.0.1:{port}/mcp",
                                 data=json.dumps(body).encode("utf-8"),
                                 method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8")
            return r.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def _stdio_tools(tmp_path):
    """tools/list from a real stdio `arcaeon mcp` subprocess."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        [sys.executable, "-m", "arcaeon", "mcp"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
        env=_env(tmp_path), cwd=str(tmp_path))
    q = queue.Queue()
    threading.Thread(target=_lines, args=(proc.stdout, q), daemon=True).start()

    def send(msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    def answer(want_id):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                line = q.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line is None:
                break
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if msg.get("id") == want_id:
                return msg
        pytest.fail(f"the stdio server gave no answer to id {want_id}")

    try:
        send(INIT)
        assert "result" in answer(1)
        send(INITIALIZED)
        send(LIST)
        return answer(2)["result"]["tools"]
    finally:
        _stop(proc)


def _by_name(tools):
    return {t["name"]: {"description": t.get("description"),
                        "inputSchema": t.get("inputSchema")} for t in tools}


@needs_extra
def test_initialize_and_tools_list_over_http_equal_stdio(http_server, tmp_path):
    port, token = http_server["port"], http_server["token"]
    status, init = _post(port, INIT, token=token)
    assert status == 200, init
    assert init["result"]["serverInfo"]["name"]
    assert "tools" in init["result"]["capabilities"]
    status, _ = _post(port, INITIALIZED, token=token)
    assert status in (200, 202)
    status, listed = _post(port, LIST, token=token)
    assert status == 200, listed
    over_http = listed["result"]["tools"]
    assert len(over_http) == 20  # the second reader made it twenty

    over_stdio = _stdio_tools(tmp_path / "stdio")
    assert sorted(t["name"] for t in over_http) == sorted(t["name"] for t in over_stdio)
    assert _by_name(over_http) == _by_name(over_stdio)

    from arcaeon.mcp.server import FREE_TOOLS, PAID_TOOLS
    assert set(_by_name(over_http)) == set(FREE_TOOLS) | set(PAID_TOOLS)


@needs_extra
def test_no_token_and_wrong_token_are_refused(http_server):
    from arcaeon.serve import auth
    port = http_server["port"]
    status, body = _post(port, INIT)
    assert status == 401
    assert body["error"] == auth.NO_TOKEN
    status, body = _post(port, INIT, token="not-the-token")
    assert status == 401
    assert body["error"] == auth.WRONG_TOKEN
    assert http_server["token"] not in json.dumps(body)
    ok, _ = _post(port, INIT, token=http_server["token"])
    assert ok == 200


@needs_extra
def test_loopback_only_host_header_refused_like_serve(http_server):
    assert http_server["host"] == "127.0.0.1"
    assert "loopback only" in http_server["line"]
    port, token = http_server["port"], http_server["token"]
    for bad in ("evil.example", f"evil.example:{port}", f"192.168.1.20:{port}",
                "127.0.0.1.nip.io"):
        status, body = _post(port, INIT, token=token, host=bad)
        assert status == 400, bad
        assert body == {"error": "this server answers only on its loopback address",
                        "exit": 2}
    for good in (f"127.0.0.1:{port}", f"localhost:{port}"):
        status, _ = _post(port, INIT, token=token, host=good)
        assert status == 200, good


def test_http_without_the_extra_fails_closed(tmp_path):
    """The SDK made unimportable in the child: COULD NOT LOOK, exit 3, names the extra."""
    code = ("import sys; sys.modules['mcp'] = None; "
            "from arcaeon.cli import main; "
            "sys.exit(main(['mcp', '--http', '--port', '0']))")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       encoding="utf-8", env=_env(tmp_path), cwd=str(tmp_path),
                       timeout=60, stdin=subprocess.DEVNULL)
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)
    assert "COULD NOT LOOK" in r.stderr
    assert "arcaeon[mcp]" in r.stderr
    assert "listening" not in r.stdout
    assert not (tmp_path / "home" / "serve.token").exists()
