"""proxy --policy FILE: system-prompt and policy files pinned by hash in the
session's first row, via arcaeon.record.row.file_pin. Contents never land."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from arcaeon.record.row import RAW_BYTES_PREFIX, file_pin

SRC = str(Path(__file__).resolve().parents[1] / "src")
ECHO = [sys.executable, "-m", "arcaeon.record.adapter._echo_server"]
SECRET_PROMPT = "You are the purchasing agent. CANARY-7f3e-do-not-log. Never refund."
SECRET_POLICY = '{"max_refund": 0, "canary": "POLICY-CANARY-19a2"}'
STREAM = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "echo", "arguments": {"text": "hi"}}}) + "\n").encode()


def _run(tmp_path, *extra):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    ledger = tmp_path / "seam.jsonl"
    argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger", str(ledger),
            *extra, "--", *ECHO]
    p = subprocess.run(argv, input=STREAM, capture_output=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    return ledger


def _files(tmp_path):
    prompt = tmp_path / "system_prompt.txt"
    prompt.write_text(SECRET_PROMPT, encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(SECRET_POLICY, encoding="utf-8")
    return prompt, policy


def test_policy_files_are_pinned_by_sha256_in_the_first_row(tmp_path):
    prompt, policy = _files(tmp_path)
    ledger = _run(tmp_path, "--policy", str(prompt), "--policy", str(policy))
    first = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
    assert first["evt"] == "session_begin"
    pins = first["policy_pins"]
    assert [p["path"] for p in pins] == [str(prompt), str(policy)]
    for pin, f in zip(pins, (prompt, policy)):
        want = hashlib.sha256(f.read_bytes()).hexdigest()
        assert pin["sha256"] == want
        assert pin["digest"] == RAW_BYTES_PREFIX + want
        assert pin["bytes"] == f.stat().st_size


def test_policy_file_contents_are_absent_from_the_ledger(tmp_path):
    prompt, policy = _files(tmp_path)
    ledger = _run(tmp_path, "--policy", str(prompt), "--policy", str(policy))
    text = ledger.read_text(encoding="utf-8")
    assert "CANARY-7f3e" not in text
    assert "POLICY-CANARY-19a2" not in text
    assert "purchasing agent" not in text
    assert "max_refund" not in text


def test_policy_pin_changes_when_the_file_changes(tmp_path):
    prompt, _ = _files(tmp_path)
    a = file_pin(prompt)
    prompt.write_text(SECRET_PROMPT + " ", encoding="utf-8")
    assert file_pin(prompt)["sha256"] != a["sha256"]


def test_missing_policy_file_is_pinned_as_missing_not_dropped(tmp_path):
    ledger = _run(tmp_path, "--policy", str(tmp_path / "gone.txt"))
    first = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
    (pin,) = first["policy_pins"]
    assert pin["reason_word"] == "missing" and "sha256" not in pin


def test_no_policy_flag_no_policy_field(tmp_path):
    ledger = _run(tmp_path)
    first = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
    assert "policy_pins" not in first
