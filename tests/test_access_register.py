"""tape.access_register: every file, URL and record name seen in tools/call
arguments, as name + digest, never contents."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from arcaeon.record.adapter.tape import TapeWriter, access_register, extract_access
from arcaeon.record.row import digest_json

SRC = str(Path(__file__).resolve().parents[1] / "src")
ECHO = [sys.executable, "-m", "arcaeon.record.adapter._echo_server"]


def _entries(reg, kind):
    return {e["name"]: e for e in reg["entries"] if e["kind"] == kind}


def test_extract_access_finds_files_urls_and_records():
    found = extract_access({
        "path": "/srv/data/report.csv",
        "url": "https://user:pw@api.example.com:8443/v1/items?token=SECRET#frag",
        "table": "customers",
        "record_id": 42,
        "nested": {"output_path": "C:\\out\\x.txt", "note": "just text"},
        "attachments": ["file:///tmp/a.pdf", "./rel/b.txt"],
    })
    by = {(e["kind"], e["name"]) for e in found}
    assert ("file", "/srv/data/report.csv") in by
    assert ("url", "https://api.example.com:8443/v1/items") in by
    assert ("record", "customers") in by and ("record", "42") in by
    assert ("file", "C:\\out\\x.txt") in by
    assert ("file", "/tmp/a.pdf") in by and ("file", "./rel/b.txt") in by
    assert not any(e["name"] == "just text" for e in found)
    text = json.dumps(found)
    assert "SECRET" not in text and "pw@" not in text      # never in the name
    url = next(e for e in found if e["kind"] == "url")
    assert url["digest"] == digest_json(
        "https://user:pw@api.example.com:8443/v1/items?token=SECRET#frag")


def test_access_register_from_a_tape_lists_names_digests_and_calls(tmp_path):
    tape = tmp_path / "agent.tape.jsonl"
    w = TapeWriter(tape, access_names=True)
    for i, args in enumerate([{"path": "/etc/app.conf"},
                              {"url": "https://example.com/a"},
                              {"path": "/etc/app.conf", "table": "orders"}]):
        idx = w.open_call({"name": f"t{i}", "arguments": args}, rpc_id=i)
        w.close_call(idx, {"result": {"content": []}})
    reg = access_register(tape)
    files, urls, recs = (_entries(reg, k) for k in ("file", "url", "record"))
    assert files["/etc/app.conf"]["calls"] == [1, 3]
    assert files["/etc/app.conf"]["tools"] == ["t0", "t2"]
    assert files["/etc/app.conf"]["digest"] == digest_json("/etc/app.conf")
    assert "https://example.com/a" in urls and "orders" in recs
    assert reg["calls"] == 3 and reg["calls_without_names"] == 0


def test_access_register_never_holds_file_contents(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("CONTENTS-CANARY-55", encoding="utf-8")
    tape = tmp_path / "t.jsonl"
    w = TapeWriter(tape, access_names=True)
    w.close_call(w.open_call({"name": "read", "arguments": {"path": str(secret)}}, 1),
                 {"result": {"content": [{"type": "text", "text": "CONTENTS-CANARY-55"}]}})
    reg = access_register(tape)
    assert str(secret) in _entries(reg, "file")
    assert "CONTENTS-CANARY-55" not in json.dumps(reg)
    assert "CONTENTS-CANARY-55" not in tape.read_text(encoding="utf-8")


def test_default_tape_carries_no_names_and_the_register_says_so(tmp_path):
    tape = tmp_path / "t.jsonl"
    w = TapeWriter(tape)
    w.close_call(w.open_call({"name": "read", "arguments": {"path": "/a/b"}}, 1),
                 {"result": {}})
    assert "/a/b" not in tape.read_text(encoding="utf-8")
    reg = access_register(tape)
    assert reg["entries"] == [] and reg["calls_without_names"] == 1


def test_access_register_missing_file_is_could_not_look(tmp_path):
    reg = access_register(tmp_path / "nope.jsonl")
    assert reg["could_not_look"]["reason_word"] == "missing"


def test_access_register_through_the_proxy(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    tape = tmp_path / "agent.tape.jsonl"
    stream = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "echo", "arguments": {"text": "hi", "path": "/data/in.csv",
                                      "url": "http://h.example/x?key=K"}}}) + "\n").encode()
    argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger",
            str(tmp_path / "seam.jsonl"), "--tape", str(tape), "--access-names", "--", *ECHO]
    p = subprocess.run(argv, input=stream, capture_output=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    reg = access_register(tape)
    assert "/data/in.csv" in _entries(reg, "file")
    assert "http://h.example/x" in _entries(reg, "url")
    assert "key=K" not in json.dumps(reg)


def test_access_register_reads_a_raw_seam_log(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    seam = tmp_path / "seam.jsonl"
    stream = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "echo", "arguments": {"text": "hi", "file": "notes.md"}}}) + "\n").encode()
    argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger", str(seam),
            "--raw", "--", *ECHO]
    subprocess.run(argv, input=stream, capture_output=True, env=env, timeout=120)
    assert "notes.md" in _entries(access_register(seam), "file")
