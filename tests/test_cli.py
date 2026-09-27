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
from arcaeon import verdict as V

ROOT = Path(__file__).resolve().parents[1]

#: The council's list (COUNCIL_MERGE_SHAPE_2026-09-23.md, "CLI verbs"), verbatim.
COUNCIL_VERBS = ["log", "verify", "reconcile", "pin", "seal", "stamp", "vet", "badge",
                 "receipt", "audit", "once", "baseline", "compact", "distill", "dedup",
                 "meter", "proxy", "mcp", "credits", "buy", "selftest", "version"]
#: Verbs added after the council's list, each with its authority.
#: deal: DEAL_LANE_DESIGN_2026-09-24.md (the witnessed-transaction lane).
#: status: Daniel's HUD slice 1 (batch lane B, B015), reads the activity journal.
ADDED_VERBS = ["deal", "status"]
#: Registered up front by the 9/27 plug-in batch (BATCH_OPUS_2026-09-27_PLUGIN.md,
#: K001), each dispatched lazily to a module a later item builds.
PLUGIN_VERBS = ["serve", "connect", "schema", "second-read", "evidence-pack", "export",
                "mandate", "doctor", "demo", "open"]
ALL_VERBS = COUNCIL_VERBS + ADDED_VERBS + PLUGIN_VERBS


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
    assert "reconcile" in p.stdout and "arcaeon 0.10.0" in p.stdout


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
    if not cli.verb_built(verb):
        pytest.skip(f"{verb}: registered, not built in this checkout")
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
    if not cli.verb_built(verb):
        pytest.skip(f"{verb}: registered, not built in this checkout")
    assert cli.main([verb, "--help"]) == 0
    out = capsys.readouterr()
    usage = [ln for ln in (out.out + "\n" + out.err).splitlines() if ln.startswith("usage:")]
    assert usage, (verb, out.out[:300])
    assert usage[0].startswith(f"usage: arcaeon {verb}"), (verb, usage[0])
    assert usage[0][len(f"usage: arcaeon {verb}"):][:1] in ("", " "), (verb, usage[0])


@pytest.mark.parametrize("verb", ALL_VERBS)
def test_every_verb_version_names_arcaeon_verb(verb, capsys, monkeypatch):
    """0.9.0: `arcaeon audit --version` printed "arcaeon-audit 0.1.8" (the moved
    tool's own argparse version), and most verbs had no --version at all. 0.9.1:
    every verb answers `arcaeon <verb> <arcaeon version>`, exit 0, touching
    nothing (no server, no network, no subcommand run)."""
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    assert cli.main([verb, "--version"]) == 0
    out = capsys.readouterr()
    assert out.out.strip() == f"arcaeon {verb} 0.10.0", (verb, out.out[:200])
    assert out.err == ""


def test_plugin_verbs_are_lazy_and_each_names_a_batch_item():
    assert sorted(cli.LAZY_VERBS) == sorted(PLUGIN_VERBS)
    for verb, (mod, item) in cli.LAZY_VERBS.items():
        assert mod.startswith("arcaeon."), verb
        assert item[0] == "K" and item[1:].isdigit(), verb


def test_an_unbuilt_verb_says_so_and_exits_2(capsys, monkeypatch):
    monkeypatch.setitem(cli.LAZY_VERBS, "serve", ("arcaeon.no_such_module_k001.cli", "K004"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    assert cli.verb_built("serve") is False
    assert cli.main(["serve", "--port", "0"]) == V.EXIT_USAGE
    out = capsys.readouterr()
    assert out.err.strip() == "arcaeon serve: not built in this checkout"
    assert out.out == ""


def test_an_unbuilt_verb_from_the_command_line(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), ARCAEON_JOURNAL="0")
    missing = [v for v in PLUGIN_VERBS if not cli.verb_built(v)]
    if not missing:
        pytest.skip("every plug-in verb is built in this checkout")
    verb = missing[0]
    p = subprocess.run([sys.executable, "-m", "arcaeon", verb], capture_output=True,
                       text=True, env=env, cwd=str(tmp_path), timeout=120)
    assert p.returncode == 2
    assert p.stderr.strip() == f"arcaeon {verb}: not built in this checkout"


def test_a_built_lazy_verb_runs_its_module_main(tmp_path, monkeypatch):
    (tmp_path / "fake_k001_verb.py").write_text(
        "SEEN = []\n"
        "def main(argv):\n"
        "    SEEN.append(list(argv))\n"
        "    return 3\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setitem(cli.LAZY_VERBS, "demo", ("fake_k001_verb", "K116"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    assert cli.verb_built("demo") is True
    assert cli.main(["demo", "--x", "y"]) == 3
    import fake_k001_verb
    assert fake_k001_verb.SEEN == [["--x", "y"]]


def test_version_flag_after_a_subcommand_and_dash_v(capsys):
    assert cli.main(["audit", "verify", "--version"]) == 0
    assert capsys.readouterr().out.strip() == "arcaeon audit 0.10.0"
    assert cli.main(["meter", "-V"]) == 0
    assert capsys.readouterr().out.strip() == "arcaeon meter 0.10.0"


def test_version_after_double_dash_is_an_argument_not_the_flag(monkeypatch):
    seen = []
    monkeypatch.setitem(cli.HANDLERS, "log", lambda argv: seen.append(argv) or 0)
    assert cli.main(["log", "--", "--version"]) == 0
    assert seen == [["--", "--version"]]


def test_once_help_is_in_the_arcaeon_form(capsys):
    """0.9.0's `arcaeon once --help` opened "arcaeon-once CLI" and showed
    `python -m arcaeon.record.once.cli` examples."""
    assert cli.main(["once", "--help"]) == 0
    out = capsys.readouterr().out
    assert "arcaeon-once" not in out and "python -m" not in out
    assert "arcaeon once -- inspect a key's receipt" in out
    assert 'arcaeon once receipt ops.log.jsonl "refund:pi_123"' in out


def test_version_verb_names_every_family(capsys):
    assert cli.main(["version"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("arcaeon 0.10.0")
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
    assert cli.main(["credits", "--json"]) == 0
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


# --- the activity journal (B013) ----------------------------------------------------

@pytest.fixture
def jhome(tmp_path, monkeypatch):
    d = tmp_path / "arc_home"
    monkeypatch.setenv("ARCAEON_HOME", str(d))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    return d


def _journal_rows(d):
    f = d / "activity.jsonl"
    if not f.exists():
        return []
    return [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_journal_one_line_per_invocation(jhome, tmp_path, capsys):
    import hashlib
    p = tmp_path / "a.jsonl"
    assert cli.main(["log", str(p), '{"op": "one"}']) == 0
    assert cli.main(["verify", str(p)]) == 0
    assert cli.main(["verify", str(tmp_path / "missing.jsonl")]) == 3
    assert cli.main(["log", str(p)]) == 2
    capsys.readouterr()
    rows = _journal_rows(jhome)
    assert [(r["verb"], r["exit"], r["word"]) for r in rows] == [
        ("log", 0, "OK"), ("verify", 0, "VERIFIED"),
        ("verify", 3, V.COULD_NOT_LOOK), ("log", 2, "BAD USAGE")]
    want = hashlib.sha256(os.path.normcase(os.path.abspath(str(p))).encode()).hexdigest()
    assert rows[0]["target"] == rows[1]["target"] == want


def test_journal_skips_help_version_and_unknown_verbs(jhome, capsys):
    assert cli.main(["verify", "--help"]) == 0
    assert cli.main(["verify", "--version"]) == 0
    assert cli.main(["--help"]) == 0
    assert cli.main(["frobnicate"]) == 2
    capsys.readouterr()
    assert _journal_rows(jhome) == []


def test_journal_records_an_internal_error_as_could_not_look(jhome, monkeypatch, capsys):
    def boom(argv):
        raise RuntimeError("secret detail")
    monkeypatch.setitem(cli.HANDLERS, "log", boom)
    assert cli.main(["log", "x.jsonl", "{}"]) == 3
    capsys.readouterr()
    rows = _journal_rows(jhome)
    assert len(rows) == 1 and rows[0]["exit"] == 3 and rows[0]["word"] == V.COULD_NOT_LOOK


def test_journal_failure_never_changes_the_exit_code(jhome, monkeypatch, tmp_path, capsys):
    from arcaeon import journal
    monkeypatch.setattr(journal, "append", lambda *a, **k: 1 / 0)
    assert cli.main(["log", str(tmp_path / "a.jsonl"), '{"op": 1}']) == 0
    assert cli.main(["verify", str(tmp_path / "nope.jsonl")]) == 3
    assert "Traceback" not in capsys.readouterr().err


def test_journal_privacy_through_the_cli(jhome, tmp_path, capsys):
    target = tmp_path / "secret_customer_ledger.jsonl"
    cli.main(["log", str(target), '{"op": "wire 5000 to acct 99"}'])
    cli.main(["verify", str(target)])
    capsys.readouterr()
    raw = (jhome / "activity.jsonl").read_text(encoding="utf-8")
    for needle in (str(target), target.name, "secret_customer", "wire 5000", "acct 99"):
        assert needle not in raw, needle


# --- log --field / log - (B018) -----------------------------------------------------

def _ledger_rows(p):
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_log_field_builds_the_row_without_json_quoting(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    assert cli.main(["log", str(p), "--field", "tool=search", "--field", "query=weather now",
                     "--field=note=a=b"]) == 0
    assert cli.main(["log", str(p), "--field", "n:=5", "--field", "ok:=true",
                     "--field", "tags:=[1,2]", "--field", "s=5"]) == 0
    assert cli.main(["verify", str(p)]) == 0
    capsys.readouterr()
    rows = _ledger_rows(p)
    assert rows[0]["tool"] == "search" and rows[0]["query"] == "weather now"
    assert rows[0]["note"] == "a=b"
    assert rows[1]["n"] == 5 and rows[1]["ok"] is True and rows[1]["tags"] == [1, 2]
    assert rows[1]["s"] == "5"


def test_log_field_over_a_json_row(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    assert cli.main(["log", str(p), '{"op": "one", "x": 1}', "--field", "x=over"]) == 0
    capsys.readouterr()
    r = _ledger_rows(p)[0]
    assert r["op"] == "one" and r["x"] == "over"


@pytest.mark.parametrize("bad", [["--field"], ["--field", "novalue"], ["--field", "=v"],
                                 ["--field", "n:=not json"], ["--frob"]])
def test_log_field_bad_usage_writes_nothing(tmp_path, capsys, bad):
    p = tmp_path / "a.jsonl"
    assert cli.main(["log", str(p), *bad]) == 2
    capsys.readouterr()
    assert not p.exists()


def test_log_stdin_reads_the_row(tmp_path, monkeypatch, capsys):
    import io
    p = tmp_path / "a.jsonl"
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"op": "from stdin"}\n'))
    assert cli.main(["log", str(p), "-"]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"op": "two"}'))
    assert cli.main(["log", str(p), "-", "--field", "who=me"]) == 0
    capsys.readouterr()
    rows = _ledger_rows(p)
    assert rows[0]["op"] == "from stdin" and rows[1] == {**rows[1], "op": "two", "who": "me"}


def test_log_stdin_via_a_real_pipe(tmp_path):
    p = tmp_path / "a.jsonl"
    r = subprocess.run([sys.executable, "-m", "arcaeon", "log", str(p), "-"],
                       input='{"op": "piped"}', capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert _ledger_rows(p)[0]["op"] == "piped"


def test_log_stdin_not_json_is_bad(tmp_path, monkeypatch, capsys):
    import io
    p = tmp_path / "a.jsonl"
    monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))
    assert cli.main(["log", str(p), "-"]) == 1
    capsys.readouterr()


# --- credits as a sentence, version names extras and whether a key is set (B019) -----

FAKE_KEY = "wk_FAKE_do_not_print_7f3a9c"


def test_credits_human_sentence(monkeypatch, capsys):
    from arcaeon import remote
    monkeypatch.setenv("ARCAEON_KEY", FAKE_KEY)
    monkeypatch.setattr(remote, "_request", lambda *a, **k: (200, {
        "ok": True, "key_id": "abc", "credit_balance": 1000,
        "free_tier": {"plan": "free", "month": "2026-09", "used": 7, "cap": 100}}))
    assert cli.main(["credits"]) == 0
    out = capsys.readouterr().out
    assert out.strip() == "1000 credits left, 7 of 100 free pins used this month"
    assert FAKE_KEY not in out


def test_credits_human_json_is_the_raw_answer(monkeypatch, capsys):
    from arcaeon import remote
    monkeypatch.setenv("ARCAEON_KEY", FAKE_KEY)
    monkeypatch.setattr(remote, "_request", lambda *a, **k: (200, {
        "ok": True, "credit_balance": 3, "free_tier": {"used": 0, "cap": 100}}))
    assert cli.main(["credits", "--json"]) == 0
    raw = json.loads(capsys.readouterr().out)
    assert raw["credit_balance"] == 3 and raw["free_tier"]["cap"] == 100
    assert cli.main(["credits", "--frob"]) == 2
    capsys.readouterr()


def test_version_key_set_is_named_never_printed(monkeypatch, capsys):
    monkeypatch.setenv("ARCAEON_KEY", FAKE_KEY)
    assert cli.main(["version"]) == 0
    out = capsys.readouterr()
    assert FAKE_KEY not in out.out and FAKE_KEY not in out.err
    assert "FAKE" not in out.out
    line = next(ln for ln in out.out.splitlines() if "extras:" in ln)
    assert line.strip().endswith("key: set")


def test_version_key_not_set_and_extras_listed(monkeypatch, capsys):
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    assert cli.main(["version"]) == 0
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if "extras:" in ln)
    assert line.strip().endswith("key: not set")
    import importlib.util
    if importlib.util.find_spec("cryptography"):
        assert "sign" in line
    extras = line.split("extras:")[1].split(";")[0].strip()
    assert extras == "none" or set(extras.split(", ")) <= {"mcp", "ts", "sign"}


# --- pin --remote with no --ns (B020) -----------------------------------------------

def _refuse_unless(prefix):
    """A stub witness: 403 naming `prefix` unless the namespace starts with it."""
    sent = []

    def post(url, body, key, timeout=None):
        sent.append(body["namespace"])
        if not body["namespace"].startswith(prefix):
            return 403, {"error": f'this key may only pin namespaces starting with "{prefix}"'}
        return 201, {"ok": True, "namespace": body["namespace"]}
    return sent, post


def test_pin_ns_from_key_retries_once_under_the_named_prefix(tmp_path, monkeypatch, capsys):
    from arcaeon.remote import sealed_scan, witness
    sealed_scan._reset_prefix_cache()
    monkeypatch.setenv("ARCAEON_KEY", "wk_test_pin_ns")
    sent, post = _refuse_unless("wk-ab12-")
    monkeypatch.setattr(witness, "_http_post", post)
    p = tmp_path / "secret_name.jsonl"
    cli.main(["log", str(p), '{"op": "one"}'])
    capsys.readouterr()
    assert cli.main(["pin", str(p), "--remote"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(sent) == 2
    assert sent[0].startswith("arcaeon-ledger-") and sent[1].startswith("wk-ab12-ledger-")
    assert sent[0][len("arcaeon-"):] == sent[1][len("wk-ab12-"):]
    assert out["ok"] is True and out["namespace"] == sent[1]
    assert "secret" not in sent[1]
    # the same process now goes straight to the derived namespace: one request
    cli.main(["log", str(p), '{"op": "two"}'])
    capsys.readouterr()
    assert cli.main(["pin", str(p), "--remote"]) == 0
    capsys.readouterr()
    assert sent[2:] == [sent[1]]
    sealed_scan._reset_prefix_cache()


def test_pin_ns_from_key_differs_per_ledger(tmp_path, monkeypatch, capsys):
    from arcaeon.remote import sealed_scan, witness
    sealed_scan._reset_prefix_cache()
    monkeypatch.setenv("ARCAEON_KEY", "wk_test_pin_ns")
    sent, post = _refuse_unless("arcaeon-")
    monkeypatch.setattr(witness, "_http_post", post)
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    cli.main(["log", str(a), '{"op": "a"}'])
    cli.main(["log", str(b), '{"op": "b"}'])
    assert cli.main(["pin", str(a), "--remote"]) == 0
    assert cli.main(["pin", str(b), "--remote"]) == 0
    capsys.readouterr()
    assert len(sent) == 2 and sent[0] != sent[1]
    sealed_scan._reset_prefix_cache()


def test_pin_ns_from_key_explicit_ns_is_never_second_guessed(tmp_path, monkeypatch, capsys):
    from arcaeon.remote import sealed_scan, witness
    sealed_scan._reset_prefix_cache()
    monkeypatch.setenv("ARCAEON_KEY", "wk_test_pin_ns")
    sent, post = _refuse_unless("wk-ab12-")
    monkeypatch.setattr(witness, "_http_post", post)
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": "one"}'])
    assert cli.main(["pin", str(p), "--ns", "demo", "--remote"]) == 1
    capsys.readouterr()
    assert sent == ["demo"]
    sealed_scan._reset_prefix_cache()


def test_pin_ns_from_key_witness_file_still_needs_ns(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": "one"}'])
    assert cli.main(["pin", str(p), "--witness", str(tmp_path / "w.jsonl")]) == 2
    assert "--ns is required with --witness" in capsys.readouterr().err
    assert not (tmp_path / "w.jsonl").exists()


def test_pin_ns_from_key_without_a_key_sends_nothing(tmp_path, monkeypatch, capsys):
    from arcaeon.remote import witness
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.setattr(witness, "_http_post", lambda *a, **k: pytest.fail("network used"))
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": "one"}'])
    assert cli.main(["pin", str(p), "--remote"]) == 1
    assert "ARCAEON_KEY" in capsys.readouterr().out


# --- credits / stamp: a request that never completed is COULD NOT LOOK (B016) --------

def _offline(*a, **k):
    return 0, {"error": "witness unreachable: [Errno 11001] getaddrinfo failed"}


def test_credits_offline_is_could_not_look_network(monkeypatch, capsys):
    from arcaeon import remote
    monkeypatch.setenv("ARCAEON_KEY", "k_test")
    monkeypatch.setattr(remote, "_request", _offline)
    assert cli.main(["credits"]) == 3
    out = capsys.readouterr().out
    assert out.startswith("COULD NOT LOOK (network): looked for your balance at ")
    assert cli.main(["credits", "--json"]) == 3
    j = json.loads(capsys.readouterr().out)
    assert j["verdict"] == "COULD NOT LOOK" and j["reason_word"] == "network"
    assert j["looked_for"] == "your balance" and j["where"].endswith("/api/balance")


def test_credits_refusal_with_an_answer_stays_bad(monkeypatch, capsys):
    from arcaeon import remote
    monkeypatch.setenv("ARCAEON_KEY", "k_test")
    monkeypatch.setattr(remote, "_request", lambda *a, **k: (401, {"error": "invalid key"}))
    assert cli.main(["credits"]) == 1
    capsys.readouterr()


def test_stamp_offline_is_could_not_look_network(monkeypatch, tmp_path, capsys):
    from arcaeon import remote
    f = tmp_path / "doc.txt"
    f.write_bytes(b"x")
    monkeypatch.setattr(remote, "_request", _offline)
    assert cli.main(["stamp", str(f)]) == 3
    j = json.loads(capsys.readouterr().out)
    assert j["verdict"] == "COULD NOT LOOK" and j["reason_word"] == "network"
    assert j["where"].endswith("/api/stamp") and j["looked_for"]


def test_stamp_refused_with_an_answer_stays_bad(monkeypatch, tmp_path, capsys):
    from arcaeon import remote
    f = tmp_path / "doc.txt"
    f.write_bytes(b"x")
    monkeypatch.setattr(remote, "_request", lambda *a, **k: (429, {"error": "over cap"}))
    assert cli.main(["stamp", str(f)]) == 1
    capsys.readouterr()


def test_stamp_missing_file_is_could_not_look_missing(monkeypatch, tmp_path, capsys):
    from arcaeon import remote
    monkeypatch.setattr(remote, "_request", lambda *a, **k: pytest.fail("network used"))
    missing = tmp_path / "nope.txt"
    assert cli.main(["stamp", str(missing)]) == 3
    cap = capsys.readouterr()
    j = json.loads(cap.out)
    assert j["verdict"] == "COULD NOT LOOK" and j["reason_word"] == "missing"
    assert j["where"] == str(missing) and j["looked_for"] == "the file to stamp"
    assert "nothing was sent" in cap.err
    # a directory is unreadable, also 3, also nothing sent
    assert cli.main(["stamp", str(tmp_path)]) == 3
    assert json.loads(capsys.readouterr().out)["reason_word"] == "unreadable"


# --- verify and friends: every COULD NOT LOOK names looked_for and where (B017) ------

def _cnl_json(out):
    return json.loads(out[out.index("{"):])


def test_verify_missing_file_names_looked_for_and_where(tmp_path, capsys):
    missing = tmp_path / "nope.jsonl"
    assert cli.main(["verify", str(missing)]) == 3
    cap = capsys.readouterr()
    j = json.loads(cap.out)
    assert j["verdict"] == "COULD NOT LOOK" and j["reason_word"] == "missing"
    assert j["looked_for"] == "a ledger file" and j["where"] == str(missing)
    assert "looked for a ledger file in " + str(missing) in cap.err


def test_verify_bounded_and_empty_name_their_reason_word(tmp_path, capsys):
    b = tmp_path / "b.jsonl"
    b.write_text('{"a": 1}\n', encoding="utf-8")
    assert cli.main(["verify", str(b)]) == 3
    j = json.loads(capsys.readouterr().out)
    assert j["reason_word"] == "bounded" and j["where"] == str(b) and j["looked_for"]
    e = tmp_path / "e.jsonl"
    e.write_text("", encoding="utf-8")
    assert cli.main(["verify", str(e)]) == 3
    assert json.loads(capsys.readouterr().out)["reason_word"] == "empty"


def test_verify_green_carries_no_could_not_look_keys(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": 1}'])
    capsys.readouterr()
    assert cli.main(["verify", str(p)]) == 0
    j = json.loads(capsys.readouterr().out)
    assert "looked_for" not in j and "reason_word" not in j


def test_verify_log_refusal_prints_and_emits_looked_for(tmp_path, capsys):
    p = tmp_path / "bin.jsonl"
    p.write_bytes(b"\xff\xfe\x00binary\n")
    assert cli.main(["log", str(p), '{"op": 1}']) == 3
    cap = capsys.readouterr()
    j = _cnl_json(cap.out)
    assert j["verdict"] == "COULD NOT LOOK" and j["reason_word"] == "unreadable"
    assert j["where"] == str(p) and j["looked_for"] == "a chained last row to append after"
    assert "looked for: a chained last row to append after; where: " + str(p) in cap.err
    assert p.read_bytes() == b"\xff\xfe\x00binary\n"


def test_verify_witness_file_refusal_prints_and_emits_looked_for(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": 1}'])
    w = tmp_path / "w.jsonl"
    w.write_text('{"not": "a pin"}\n', encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 3
    cap = capsys.readouterr()
    j = json.loads(cap.out)
    assert j["reason_word"] == "unreadable" and j["where"] == str(w)
    assert j["looked_for"] == "a witness pin file to append to" and "error" in j
    assert "looked for: a witness pin file to append to" in cap.err


def test_verify_pin_of_a_bounded_ledger_emits_looked_for(tmp_path, capsys):
    b = tmp_path / "b.jsonl"
    b.write_text('{"a": 1}\n', encoding="utf-8")
    assert cli.main(["pin", str(b), "--ns", "demo", "--witness", str(tmp_path / "w.jsonl")]) == 3
    j = json.loads(capsys.readouterr().out)
    assert j["reason_word"] == "bounded" and j["where"] == str(b) and j["looked_for"]


def test_verify_unindexable_ledger_emits_looked_for(tmp_path, capsys):
    p = tmp_path / "bin.jsonl"
    p.write_bytes(b"\xff\xfe\x00binary\n")
    assert cli.main(["once", "rebuild-index", str(p)]) == 3
    cap = capsys.readouterr()
    j = _cnl_json(cap.out)
    assert j["reason_word"] == "unreadable" and j["where"] == str(p)
    assert j["looked_for"] == "UTF-8 JSON lines to index"
    assert "looked for: UTF-8 JSON lines to index" in cap.err


def test_verify_rows_since_pin(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    w = tmp_path / "pins.jsonl"
    cli.main(["log", str(p), '{"op": 1}'])
    cli.main(["log", str(p), '{"op": 2}'])
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 0
    for i in range(3):
        cli.main(["log", str(p), json.dumps({"op": 10 + i})])
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(w)]) == 0
    cap = capsys.readouterr()
    j = json.loads(cap.out)
    assert j["since_pin"]["rows_since_pin"] == 3 and j["since_pin"]["namespace"] == "demo"
    assert j["since_pin"]["pinned_rows"] == 2
    assert "rows added since the last pin (demo, 2 rows): 3" in cap.err
    assert cli.main(["verify", str(p), "--witness", str(w), "--ns", "demo"]) == 0
    assert json.loads(capsys.readouterr().out)["since_pin"]["rows_since_pin"] == 3


def test_verify_rows_since_pin_truncation_is_broken(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    w = tmp_path / "pins.jsonl"
    for i in range(3):
        cli.main(["log", str(p), json.dumps({"op": i})])
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 0
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    p.write_text("".join(lines[:2]), encoding="utf-8")        # cut the last row off
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(w)]) == 1
    cap = capsys.readouterr()
    j = json.loads(cap.out)
    assert j["verdict"] == "BROKEN" and j["since_pin"]["truncated"] is True
    assert "fewer row(s) than its last pin" in cap.err


def test_verify_rows_since_pin_absent_or_ambiguous(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    cli.main(["log", str(p), '{"op": 1}'])
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(tmp_path / "none.jsonl")]) == 0
    j = json.loads(capsys.readouterr().out)
    assert j["since_pin"]["rows_since_pin"] is None
    w = tmp_path / "pins.jsonl"
    cli.main(["pin", str(p), "--ns", "one", "--witness", str(w)])
    cli.main(["pin", str(p), "--ns", "two", "--witness", str(w)])
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(w)]) == 0
    assert "pass --ns" in json.loads(capsys.readouterr().out)["since_pin"]["reason"]
    assert cli.main(["verify", str(p), "--ns", "one"]) == 2
    assert cli.main(["verify", str(p), "--witness"]) == 2
    capsys.readouterr()


def test_audit_verify_accepts_a_bundle_directory(tmp_path, capsys):
    """K010b: `audit verify <dir>` resolves an exported bundle to its
    records.jsonl, as POST /v1/audit/verify does, instead of a
    Permission denied FAIL; a directory without one is COULD NOT LOOK, exit 3."""
    led = tmp_path / "a.jsonl"
    assert cli.main(["log", str(led), '{"n": 1}']) == 0
    assert cli.main(["log", str(led), '{"n": 2}']) == 0
    out = tmp_path / "bundle"
    assert cli.main(["audit", "export", str(led), str(out)]) == 0
    capsys.readouterr()
    rc_file = cli.main(["audit", "verify", str(out / "records.jsonl")])
    by_file = capsys.readouterr().out
    rc_dir = cli.main(["audit", "verify", str(out)])
    by_dir = capsys.readouterr().out
    assert rc_dir == rc_file == 0
    assert by_dir == by_file and by_dir.startswith("VERIFIED")
    empty = tmp_path / "not_a_bundle"
    empty.mkdir()
    assert cli.main(["audit", "verify", str(empty)]) == V.EXIT_COULD_NOT_LOOK
    got = capsys.readouterr().out
    assert got.startswith("COULD NOT LOOK") and "records.jsonl" in got
    assert "Permission denied" not in got
