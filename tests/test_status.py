"""`arcaeon status`: last run per verb, open COULD NOT LOOKs, balance only with a key.
No network: arcaeon.remote._request is stubbed or made to fail the test."""
import json

import pytest

from arcaeon import journal, status


@pytest.fixture
def home(tmp_path, monkeypatch):
    d = tmp_path / "arc_home"
    monkeypatch.setenv("ARCAEON_HOME", str(d))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    from arcaeon import remote
    monkeypatch.setattr(remote, "_request", lambda *a, **k: pytest.fail("network used"))
    return d


def _write(home, rows):
    home.mkdir(parents=True, exist_ok=True)
    with open(home / "activity.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def _row(t, verb, exit_, target, word=None):
    return {"t": t, "verb": verb, "word": word or journal.word_for(verb, exit_),
            "exit": exit_, "target": target}


def test_empty_journal(home, capsys):
    assert status.main([]) == 0
    out = capsys.readouterr().out
    assert "no activity recorded yet" in out
    assert "open COULD NOT LOOKs: 0" in out
    assert "balance: not checked, no key" in out


def test_last_run_per_verb_and_open_could_not_looks(home, capsys):
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    _write(home, [
        _row("2026-09-25T10:00:00Z", "verify", 3, a),
        _row("2026-09-25T10:01:00Z", "verify", 0, a),      # a retried green: closed
        _row("2026-09-25T10:02:00Z", "pin", 3, b),         # b still open
        _row("2026-09-25T10:03:00Z", "verify", 1, c),      # c broken, not a could-not-look
        _row("2026-09-25T10:04:00Z", "credits", 3, None),  # no target: not listed
    ])
    assert status.main(["--json"]) == 0
    s = json.loads(capsys.readouterr().out)
    assert s["last_run"]["verify"] == {"word": "BROKEN", "exit": 1, "t": "2026-09-25T10:03:00Z"}
    assert s["last_run"]["pin"]["word"] == "COULD NOT LOOK"
    assert s["last_run"]["credits"]["exit"] == 3
    assert [x["target"] for x in s["open_could_not_look"]] == [b]
    assert s["balance"] == {"checked": False, "reason": "not checked, no key"}


def test_human_output_names_targets_by_hash_prefix(home, capsys):
    b = "b" * 64
    _write(home, [_row("2026-09-25T10:02:00Z", "pin", 3, b)])
    assert status.main([]) == 0
    out = capsys.readouterr().out
    assert "open COULD NOT LOOKs: 1" in out
    assert "target bbbbbbbbbbbb " in out and b not in out
    assert "pin" in out and "COULD NOT LOOK" in out


def test_status_reads_what_the_cli_wrote(home, tmp_path, capsys):
    from arcaeon import cli
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": 1}'])
    cli.main(["verify", str(tmp_path / "missing.jsonl")])
    capsys.readouterr()
    assert status.main(["--json"]) == 0
    s = json.loads(capsys.readouterr().out)
    assert s["last_run"]["log"]["word"] == "OK"
    assert s["last_run"]["verify"]["word"] == "COULD NOT LOOK"
    assert len(s["open_could_not_look"]) == 1
    assert "status" not in s["last_run"]


def test_balance_with_a_key(home, monkeypatch, capsys):
    from arcaeon import remote
    monkeypatch.setenv("ARCAEON_KEY", "wk_fake_status_key_123")
    monkeypatch.setattr(remote, "_request", lambda *a, **k: (200, {
        "ok": True, "credit_balance": 42,
        "free_tier": {"plan": "free", "used": 3, "cap": 100}}))
    assert status.main([]) == 0
    out = capsys.readouterr().out
    assert "balance: 42 credits left, 3 of 100 free pins used this month" in out
    assert "wk_fake_status_key_123" not in out


def test_balance_sentence_follows_the_plan():
    """Decision 2026-09-27 8:47 AM PT: a monthly cap is shown only for a plan
    that reports one; no cap, or no plan field, shows credits only."""
    f = status.balance_sentence
    assert f({"credit_balance": 7, "free_tier": {"plan": "free", "used": 1, "cap": 100}})         == "7 credits left, 1 of 100 free pins used this month"
    assert f({"credit_balance": 500, "free_tier": {"plan": "registered", "used": 0, "cap": None}})         == "500 credits on the key"
    assert f({"credit_balance": 42, "free_tier": {"used": 3, "cap": 100}}) == "42 credits on the key"
    assert f({"credit_balance": 42}) == "42 credits on the key"
    assert f({}) == "balance read, but it carried no credit count"


def test_balance_unreachable_is_could_not_look(home, monkeypatch, capsys):
    from arcaeon import remote
    monkeypatch.setenv("ARCAEON_KEY", "wk_fake")
    monkeypatch.setattr(remote, "_request",
                        lambda *a, **k: (0, {"error": "witness unreachable: offline"}))
    assert status.main(["--json"]) == 0
    s = json.loads(capsys.readouterr().out)
    assert s["balance"]["checked"] is True and s["balance"]["status"] == 0
    assert s["balance"]["sentence"].startswith("COULD NOT LOOK (network)")


def test_bad_flag_is_usage(home, capsys):
    assert status.main(["--frob"]) == 2
    assert status.main(["--help"]) == 0
    assert "usage: arcaeon status" in capsys.readouterr().out


def test_journal_path_under_home_is_shown_with_a_tilde(monkeypatch, tmp_path, capsys):
    from pathlib import Path
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.delenv("ARCAEON_HOME", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    assert status.main([]) == 0
    first = capsys.readouterr().out.splitlines()[0]
    assert first == "arcaeon status  (journal: ~/.arcaeon/activity.jsonl)"
    assert str(tmp_path) not in first


# --- K077: mandate counts under `mandate` -------------------------------------------

def test_no_gated_sessions(home, capsys):
    assert status.main(["--json"]) == 0
    m = json.loads(capsys.readouterr().out)["mandate"]
    assert m["sessions"] == 0 and m["outside"] == 0 and m["last_session"] is None
    assert status.main([]) == 0
    assert "mandate: no gated sessions recorded" in capsys.readouterr().out


def test_session_lines_are_summed(home, capsys):
    status.note_mandate_session("s-1", {"mandate_inside": 3, "mandate_outside": 1,
                                        "mandate_could_not_look": 0,
                                        "mandate_blocked": None},
                                mode="record-only", mandate_status="loaded",
                                mandate_file_sha256="a" * 64)
    status.note_mandate_session("s-2", {"mandate_inside": 1, "mandate_outside": 2,
                                        "mandate_could_not_look": 1, "mandate_blocked": 2,
                                        "mandate_cap_exceeded": 1, "mandate_changes": 1},
                                mode="enforce", mandate_status="loaded",
                                mandate_file_sha256="b" * 64)
    assert status.main(["--json"]) == 0
    m = json.loads(capsys.readouterr().out)["mandate"]
    assert (m["sessions"], m["inside"], m["outside"], m["could_not_look"], m["blocked"],
            m["cap_exceeded"], m["changes"]) == (2, 4, 3, 1, 2, 1, 1)
    assert m["sessions_by_mode"] == {"record-only": 1, "enforce": 1}
    assert m["last_session"]["session"] == "s-2"
    assert status.main([]) == 0
    assert ("mandate: 2 gated sessions: 4 inside, 3 outside, 1 COULD NOT LOOK, "
            "2 blocked, 1 cap exceeded, 1 mandate file changes") in capsys.readouterr().out


def test_no_matching_mandate_is_summed_and_printed_only_when_non_zero(home, capsys):
    status.note_mandate_session("s-1", {"mandate_inside": 2},
                                mode="record-only", mandate_status="loaded",
                                mandate_file_sha256="a" * 64)
    assert status.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["mandate"]["no_matching_mandate"] == 0
    assert status.main([]) == 0
    out = capsys.readouterr().out
    assert "no matching mandate" not in out
    status.note_mandate_session("s-2", {"mandate_inside": 1, "mandate_outside": 1,
                                        "mandate_no_matching_mandate": 2},
                                mode="enforce", mandate_status="loaded",
                                mandate_file_sha256="a" * 64)
    status.note_mandate_session("s-3", {"mandate_no_matching_mandate": 1},
                                mode="enforce", mandate_status="loaded",
                                mandate_file_sha256="a" * 64)
    assert status.main(["--json"]) == 0
    m = json.loads(capsys.readouterr().out)["mandate"]
    assert m["no_matching_mandate"] == 3
    assert m["last_session"]["no_matching_mandate"] == 1
    assert status.main([]) == 0
    assert ("mandate: 3 gated sessions: 3 inside, 1 outside, 0 COULD NOT LOOK, "
            "0 blocked, 0 cap exceeded, 0 mandate file changes, "
            "3 no matching mandate") in capsys.readouterr().out


def test_session_line_holds_no_path_or_tool(home):
    status.note_mandate_session("s-1", {"mandate_outside": 1, "tool": "refund",
                                        "ledger": "C:/secret/seam.jsonl"},
                                mode="record-only", mandate_status="loaded",
                                mandate_file_sha256=None)
    text = (home / status.MANDATE_FILENAME).read_text(encoding="utf-8")
    assert "refund" not in text and "secret" not in text


def test_journal_off_writes_no_session_line(home, monkeypatch):
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    assert status.note_mandate_session("s", {}, mode="record-only", mandate_status="loaded",
                                       mandate_file_sha256=None) is False
    assert not (home / status.MANDATE_FILENAME).exists()


def test_bad_lines_are_skipped_and_bad_counts_are_zero(home, capsys):
    home.mkdir(parents=True, exist_ok=True)
    (home / status.MANDATE_FILENAME).write_text(
        'not json\n{"mode": "record-only", "outside": "7", "inside": -2, "blocked": true}\n',
        encoding="utf-8")
    assert status.main(["--json"]) == 0
    m = json.loads(capsys.readouterr().out)["mandate"]
    assert m["sessions"] == 1 and m["outside"] == 0 and m["inside"] == 0 and m["blocked"] == 0


def test_a_real_gated_proxy_session_shows_up(home, tmp_path, capsys):
    """End to end: a record-only stdio proxy session with one inside and one
    outside call; status --json carries the same counts as its session_end row."""
    import os
    import subprocess
    import sys
    from pathlib import Path
    src = str(Path(__file__).resolve().parents[1] / "src")
    mandate = tmp_path / "mandate.json"
    mandate.write_text(json.dumps({"who": "status-agent", "allowed_acts": ["echo"]}),
                       encoding="utf-8")
    ledger = tmp_path / "seam.jsonl"
    env = dict(os.environ)
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    env["ARCAEON_HOME"] = str(home)
    env.pop("ARCAEON_JOURNAL", None)
    env.pop("ARCAEON_ADAPTER_SELFTEST_CORRUPT", None)
    frames = [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
               "params": {"name": n, "arguments": {"text": "x"}}}
              for i, n in ((1, "echo"), (2, "refund"))]
    stdin = b"".join(json.dumps(f).encode() + b"\n" for f in frames)
    subprocess.run([sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger",
                    str(ledger), "--mandate", str(mandate), "--", sys.executable, "-m",
                    "arcaeon.record.adapter._echo_server"],
                   input=stdin, capture_output=True, env=env, timeout=60)
    rows = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines() if x]
    end = rows[-1]
    assert end["evt"] == "session_end"
    assert (end["mandate_inside"], end["mandate_outside"]) == (1, 1)
    assert status.main(["--json"]) == 0
    m = json.loads(capsys.readouterr().out)["mandate"]
    assert m["sessions"] == 1 and m["inside"] == 1 and m["outside"] == 1
    assert m["last_session"]["session"] == end["session"]
    assert m["last_session"]["mode"] == "record-only"
    assert str(tmp_path) not in (home / status.MANDATE_FILENAME).read_text(encoding="utf-8")
