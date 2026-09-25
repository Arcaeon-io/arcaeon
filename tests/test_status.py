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
        "ok": True, "credit_balance": 42, "free_tier": {"used": 3, "cap": 100}}))
    assert status.main([]) == 0
    out = capsys.readouterr().out
    assert "balance: 42 credits left, 3 of 100 free pins used this month" in out
    assert "wk_fake_status_key_123" not in out


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
