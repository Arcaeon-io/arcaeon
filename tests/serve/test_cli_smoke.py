"""K009b: `arcaeon serve` as a real subprocess, token and fence on.

Starts `py -m arcaeon serve --host 127.0.0.1 --port 0` from a temporary
served root, reads the bound port from the `listening on` line and the token
from `--print-token`, then over urllib: no token 401, wrong token 401, a
path escape with the right token 400 (`outside the served root`), an
in-root ledger with the right token 200 with a verdict word. The process is
terminated and must be gone. Loopback only.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[2] / "src")
LISTEN = re.compile(r"listening on http://127\.0\.0\.1:(\d+)")


def _env(home: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["ARCAEON_HOME"] = str(home)
    env["ARCAEON_JOURNAL"] = "0"
    env["PYTHONUNBUFFERED"] = "1"
    env.pop("ARCAEON_KEY", None)
    return env


def _call(port: int, path: str, body: dict, token: str | None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json"})
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_serve_subprocess_token_and_fence(tmp_path):
    home, root = tmp_path / "home", tmp_path / "served"
    root.mkdir()
    env = _env(home)
    tok = subprocess.run([sys.executable, "-m", "arcaeon", "serve", "--print-token"],
                         cwd=str(root), env=env, capture_output=True, text=True, timeout=120)
    assert tok.returncode == 0, tok.stderr
    token = tok.stdout.strip()
    assert len(token) >= 32

    proc = subprocess.Popen([sys.executable, "-m", "arcaeon", "serve", "--host", "127.0.0.1",
                             "--port", "0"], cwd=str(root), env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    try:
        found: dict = {}
        seen: list[str] = []

        def reader():
            for line in proc.stdout:
                seen.append(line)
                m = LISTEN.search(line)
                if m and "port" not in found:
                    found["port"] = int(m.group(1))
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        for _ in range(600):
            if "port" in found or proc.poll() is not None:
                break
            t.join(0.1)
        assert "port" in found, "".join(seen)
        port = found["port"]
        assert port != 0

        status, body = _call(port, "/v1/verify", {"ledger": "l.jsonl"}, None)
        assert status == 401 and "no token" in body["error"]
        status, body = _call(port, "/v1/verify", {"ledger": "l.jsonl"}, token + "x")
        assert (status, body["error"]) == (401, "wrong token")
        status, body = _call(port, "/v1/verify", {"ledger": "../../x"}, token)
        assert status == 400 and "outside the served root" in body["error"]
        assert body["exit"] == 2

        for n in (1, 2):
            s, b = _call(port, "/v1/log", {"ledger": "l.jsonl", "fields": {"n": n}}, token)
            assert (s, b["exit"]) == (200, 0), b
        status, body = _call(port, "/v1/verify", {"ledger": "l.jsonl"}, token)
        assert status == 200
        assert (body["verdict"], body["rows"], body["exit"]) == ("VERIFIED", 2, 0)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/",
                                     headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=60) as r:    # K100b: dashboard mounted
            assert r.status == 200 and r.headers["Content-Type"].startswith("text/html")
            assert "Arcaeon on this machine" in r.read().decode("utf-8")
        assert token not in "".join(seen)          # never in the request log
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=30)
    assert proc.poll() is not None
