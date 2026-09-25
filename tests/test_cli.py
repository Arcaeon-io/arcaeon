"""`arcaeon`: the verb list, --help, `arcaeon mcp`, and the 30-day fallback.

The fallback exists because `uvx arcaeon` meant "start the MCP server" before
0.9. Until the registry entry carries packageArguments ["mcp"]: no verb + stdin
not a terminal = start the server; no verb + a terminal = help.
"""
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from arcaeon import cli

ROOT = Path(__file__).resolve().parents[1]

#: The council's list (COUNCIL_MERGE_SHAPE_2026-09-23.md, "CLI verbs"), verbatim.
COUNCIL_VERBS = ["log", "verify", "reconcile", "pin", "seal", "stamp", "vet", "badge",
                 "receipt", "audit", "once", "baseline", "compact", "distill", "dedup",
                 "meter", "proxy", "mcp", "credits", "buy", "selftest", "version"]
#: Verbs added after the council's list, each with its authority.
#: deal: DEAL_LANE_DESIGN_2026-09-24.md (the witnessed-transaction lane).
ADDED_VERBS = ["deal"]
ALL_VERBS = COUNCIL_VERBS + ADDED_VERBS


def test_every_council_verb_exists_and_nothing_else():
    assert len(COUNCIL_VERBS) == 22
    assert sorted(cli.VERBS) == sorted(ALL_VERBS)
    assert sorted(cli.HANDLERS) == sorted(ALL_VERBS)


def test_help_lists_every_verb_and_the_exit_table(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    for verb in ALL_VERBS:
        assert f"  {verb} " in out, verb
    assert "3 COULD NOT LOOK" in out and "--legacy-exit" in out


def test_help_via_python_dash_m():
    env = dict(os.environ)
    p = subprocess.run([sys.executable, "-m", "arcaeon", "--help"], capture_output=True,
                       text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    assert "reconcile" in p.stdout and "arcaeon 0.9.0" in p.stdout


def test_unknown_verb_is_usage_2(capsys):
    assert cli.main(["frobnicate"]) == 2
    assert "unknown verb" in capsys.readouterr().err


@pytest.mark.parametrize("verb", ALL_VERBS)
def test_every_verb_answers_help_without_side_effects(verb, capsys, monkeypatch):
    """`arcaeon <verb> --help` must not start a server, touch the network, or
    fail: it prints usage and exits 0."""
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    if verb == "mcp":
        pytest.importorskip("mcp")
    rc = cli.main([verb, "--help"])
    assert rc == 0, (verb, rc)
    out = capsys.readouterr()
    assert (out.out + out.err).strip(), verb


@pytest.mark.parametrize("verb", ALL_VERBS)
def test_every_verb_usage_line_names_arcaeon_verb(verb, capsys, monkeypatch):
    """0.9.0 printed the OLD tool name in seven verbs' usage lines (prog=
    arcaeon-receipt, arcaeon-audit, arcaeon-baseline, arcaeon-meter,
    arcaeon-mcp, `python -m arcaeon.record.adapter.proxy`, and `arcaeon vet
    badge` for the badge verb). Every verb's usage now reads `arcaeon <verb>`."""
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    if verb == "mcp":
        pytest.importorskip("mcp")
    assert cli.main([verb, "--help"]) == 0
    out = capsys.readouterr()
    usage = [ln for ln in (out.out + "\n" + out.err).splitlines() if ln.startswith("usage:")]
    assert usage, (verb, out.out[:300])
    assert usage[0].startswith(f"usage: arcaeon {verb}"), (verb, usage[0])
    assert usage[0][len(f"usage: arcaeon {verb}"):][:1] in ("", " "), (verb, usage[0])


def test_version_verb_names_every_family(capsys):
    assert cli.main(["version"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("arcaeon 0.9.0")
    for mod in cli.COMPONENTS:
        assert mod in out
    assert "import failed" not in out


def test_no_verb_with_a_terminal_prints_help(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: True)
    monkeypatch.setattr(cli, "_mcp", lambda argv: called.append(argv) or 0)
    assert cli.main([]) == 0
    assert called == []
    assert "usage: arcaeon <verb>" in capsys.readouterr().out


def test_no_verb_without_a_terminal_starts_the_server(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: False)
    monkeypatch.setattr(cli, "_mcp", lambda argv: called.append(argv) or 0)
    assert cli.main([]) == 0
    assert called == [[]]
    cap = capsys.readouterr()
    assert cap.out == "", "stdout is the MCP channel; the notice must go to stderr"
    assert "arcaeon mcp" in cap.err and "1.0.0" in cap.err


def test_mcp_verb_dispatches_to_the_connector(monkeypatch):
    pytest.importorskip("mcp")
    seen = []
    import arcaeon.mcp.__main__ as mm
    monkeypatch.setattr(mm, "main", lambda argv=None, prog=None: seen.append((argv, prog)) or 0)
    assert cli.main(["mcp", "--log", "x.jsonl"]) == 0
    assert seen == [(["--log", "x.jsonl"], "arcaeon mcp")]


def test_arcaeon_mcp_tools_lists_free_and_paid(tmp_path):
    pytest.importorskip("mcp")
    env = dict(os.environ)
    env["ARCAEON_LEDGER_LOG"] = str(tmp_path / "agent.log.jsonl")
    p = subprocess.run([sys.executable, "-m", "arcaeon", "mcp", "--tools"],
                       capture_output=True, text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    assert "witness_pin" in out["paid"] and "ledger_append" in out["free"]


def _handshake(argv, tmp_path):
    env = dict(os.environ)
    env.pop("ARCAEON_KEY", None)
    env["ARCAEON_LEDGER_LOG"] = str(tmp_path / "agent.log.jsonl")
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.Popen([sys.executable, "-m", "arcaeon", *argv],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, text=True,
                            encoding="utf-8", bufsize=1)
    watchdog = threading.Timer(60.0, proc.kill)
    watchdog.start()
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                     "params": {"protocolVersion": "2025-06-18",
                                                "capabilities": {},
                                                "clientInfo": {"name": "t", "version": "0"}}})
                         + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
    finally:
        watchdog.cancel()
        proc.stdin.close()
        proc.kill()
        _, err = proc.communicate(timeout=15)
    assert line, f"no answer; stderr:\n{err}"
    return json.loads(line), err


def test_arcaeon_mcp_serves_over_real_stdio(tmp_path):
    pytest.importorskip("mcp")
    msg, _ = _handshake(["mcp"], tmp_path)
    assert msg["id"] == 1 and "serverInfo" in msg["result"], msg


def test_bare_arcaeon_on_a_pipe_still_serves_mcp(tmp_path):
    """The registry's `uvx arcaeon` (no verb, stdin a pipe) keeps working for
    the 30-day window, and says so on stderr."""
    pytest.importorskip("mcp")
    msg, err = _handshake([], tmp_path)
    assert msg["id"] == 1 and "serverInfo" in msg["result"], msg
    assert "fallback is removed in 1.0.0" in err


def test_buy_prints_the_checkout_link_from_offers_json(capsys, tmp_path):
    from arcaeon import remote
    links = remote.checkout_links()
    mini = next(x for x in links if x["plan"] == "mini")
    assert cli.main(["buy", "mini"]) == 0
    assert capsys.readouterr().out.strip() == mini["checkout"]
    assert mini["checkout"].startswith("https://buy.stripe.com/")
    assert cli.main(["buy"]) == 0
    listing = capsys.readouterr().out
    assert all(x["checkout"] in listing for x in links)
    assert cli.main(["buy", "no-such-plan"]) == 2
    custom = tmp_path / "offers.json"
    custom.write_text(json.dumps({"products": [{"id": "p", "tiers": [
        {"plan": "x", "price_usd": 1, "checkout": "https://buy.stripe.com/test_x"}]}]}),
        encoding="utf-8")
    assert cli.main(["buy", "x", "--offers", str(custom)]) == 0
    assert capsys.readouterr().out.strip() == "https://buy.stripe.com/test_x"


def test_buy_never_opens_a_browser(monkeypatch, capsys):
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: pytest.fail("opened a browser"))
    assert cli.main(["buy", "mini"]) == 0
    capsys.readouterr()


def test_bundled_offers_snapshot_matches_the_site_copy():
    """Drift check, workstation only: the snapshot `buy` reads must match the
    site's offers.json (the single source of truth for what Arcaeon charges)."""
    from arcaeon import remote
    root = os.environ.get("ARCAEON_SITE_ROOT")
    if not root:
        pytest.skip("ARCAEON_SITE_ROOT is not set (no site checkout to compare against)")
    site = Path(root) / ".well-known" / "offers.json"
    if not site.exists():
        pytest.skip("ARCAEON_SITE_ROOT has no .well-known/offers.json")
    assert json.loads(site.read_text(encoding="utf-8")) == remote.load_offers()


def test_credits_without_a_key_sends_nothing(monkeypatch, capsys):
    from arcaeon import remote
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.setattr(remote, "_request", lambda *a, **k: pytest.fail("network used"))
    assert cli.main(["credits"]) == 2
    assert "ARCAEON_KEY" in capsys.readouterr().err


def test_credits_with_a_key_reads_the_balance(monkeypatch, capsys):
    from arcaeon import remote
    monkeypatch.setenv("ARCAEON_KEY", "k_test")
    calls = []

    def fake(method, url, body=None, key=None, timeout=None):
        calls.append((method, url, key))
        return 200, {"balance": 1000}
    monkeypatch.setattr(remote, "_request", fake)
    assert cli.main(["credits"]) == 0
    assert calls == [("GET", remote.base_url() + "/api/balance", "k_test")]
    assert json.loads(capsys.readouterr().out)["balance"] == 1000


def test_stamp_sends_the_hash_not_the_bytes(monkeypatch, tmp_path, capsys):
    import hashlib
    from arcaeon import remote
    f = tmp_path / "doc.txt"
    f.write_bytes(b"secret contents")
    sent = []
    monkeypatch.setattr(remote, "_request",
                        lambda m, u, body=None, key=None, timeout=None: sent.append(body) or (201, {}))
    assert cli.main(["stamp", str(f)]) == 0
    assert sent == [{"sha256": hashlib.sha256(b"secret contents").hexdigest(), "size": 15}]
    capsys.readouterr()


def test_log_then_verify(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    assert cli.main(["log", str(p), '{"op": "one"}']) == 0
    assert cli.main(["log", str(p), '{"op": "two"}']) == 0
    assert cli.main(["verify", str(p)]) == 0
    text = p.read_text(encoding="utf-8").replace('"two"', '"TWO"')
    p.write_text(text, encoding="utf-8")
    assert cli.main(["verify", str(p)]) == 1
    capsys.readouterr()


def test_pin_to_a_local_witness_file(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": "one"}'])
    w = tmp_path / "witness.jsonl"
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 0
    capsys.readouterr()
    pins = [json.loads(x) for x in w.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert pins and pins[-1]["namespace"] == "demo" and pins[-1]["rows"] == 1


def test_pin_remote_without_a_key_sends_nothing(tmp_path, monkeypatch, capsys):
    from arcaeon.remote import witness
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.setattr(witness, "_http_post", lambda *a, **k: pytest.fail("network used"))
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": "one"}'])
    assert cli.main(["pin", str(p), "--ns", "demo", "--remote"]) == 1
    assert "ARCAEON_KEY" in capsys.readouterr().out


def test_dedup_and_distill_verbs(tmp_path, capsys):
    items = tmp_path / "items.txt"
    items.write_text("the same line\nthe same line\nsomething else entirely\n", encoding="utf-8")
    assert cli.main(["dedup", str(items)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["kept"] == ["the same line", "something else entirely"]
    assert out["report"]["removed"] == 1
    big = tmp_path / "big.json"
    big.write_text(json.dumps({"rows": [{"i": i, "text": "x" * 200} for i in range(200)]}),
                   encoding="utf-8")
    assert cli.main(["distill", str(big), "--budget", "200"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["est_tokens_after"] < out["est_tokens_before"]
    assert out["receipt"] is not None


def test_selftest_verb_runs_every_bundled_selftest(capsys):
    assert cli.main(["selftest"]) == 0
    out = capsys.readouterr().out
    summary = json.loads(out[out.rindex('{\n "selftests"'):])
    assert set(summary["selftests"]) == set(cli.SELFTESTS)
    assert summary["failed"] == []
