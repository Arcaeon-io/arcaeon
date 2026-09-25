"""tools/release_check.py: the three checks kindred labs proposed, exercised
against the script's own stub witness on 127.0.0.1. No network, no key.

The real CLI runs as `python -m arcaeon` from src/ (PYTHONPATH is the one
name the tests add to the house env). The planted failures run a fake CLI
that lies: it prints a success the witness never saw, and check B must FAIL.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses look their module up by name
    spec.loader.exec_module(mod)
    return mod


rc = _load("release_check_under_test", ROOT / "tools" / "release_check.py")

FAKE_CLI = r'''
import json, os, sys
mode = os.environ["FAKE_MODE"]
args = sys.argv[1:]
ns = args[args.index("--ns") + 1] if "--ns" in args else "mcp-vet-sealed-scans"
if mode == "lies-sealed":
    # prints a seal the witness never recorded, writes no ledger
    ss = {"sealed": True, "namespace": ns, "ledger_head": {"rows": 1, "chain": "d" * 32}}
    code = 0
else:
    raise SystemExit("unknown FAKE_MODE")
print("![mcp-vet scan report](data:,)")
print()
print(json.dumps({"verdict": "no findings in checked classes", "sealed_scan": ss}, indent=2))
sys.exit(code)
'''


@pytest.fixture()
def stub():
    s = rc.StubWitness().start()
    yield s
    s.stop()


def _run(tmp_path, stub, cli, extra_env):
    house = rc.House.build(tmp_path / "house")
    fixture = house.work / "server.py"
    fixture.write_text(rc.FIXTURE, encoding="utf-8", newline="\n")
    return rc.Run(cli=cli, house=house, fixture=fixture, witness_url=stub.url, key=stub.key,
                  stubbed=True, stub=stub, extra_env=extra_env)


def _real(tmp_path, stub):
    return _run(tmp_path, stub, [sys.executable, "-m", "arcaeon"], {"PYTHONPATH": str(ROOT / "src")})


def _fake(tmp_path, stub, mode):
    script = tmp_path / "fake_arcaeon.py"
    script.write_text(FAKE_CLI, encoding="utf-8")
    return _run(tmp_path, stub, [sys.executable, str(script)], {"FAKE_MODE": mode})


def test_the_real_cli_passes_all_three_against_the_stub_and_says_stubbed(tmp_path, stub):
    a, b, c = rc.run_checks(_real(tmp_path, stub))
    assert (a.status, b.status, c.status) == ("PASS", "STUBBED", "STUBBED"), rc.render([a, b, c])
    assert "0 requests reached the witness" in a.summary
    # B's two facts, on their own lines
    assert b.lines[0].startswith("outcome:   CLI exit 0, sealed=true")
    assert b.lines[1].startswith("read-back: witness /api/latest?ns=rc-stub-release-check-")
    assert "== sha256(fixture)" in b.lines[1]
    # C: the stub answered 403 exactly once for the outside namespace, and pinned nothing there
    assert stub.statuses_for(rc.OUTSIDE_NS) == [403]
    assert rc.OUTSIDE_NS not in stub.pins
    # B pinned under the prefix C's refusal named, and nowhere else
    assert list(stub.pins) == [b.lines[0].split("namespace ")[1].split(",")[0]]
    assert stub.key not in rc.render([a, b, c], stub.key)


def test_planted_failure_cli_prints_success_but_the_stub_has_no_pin(tmp_path, stub):
    run = _fake(tmp_path, stub, "lies-sealed")
    b = rc.check_b(run, prefix=None)
    assert b.status == "FAIL", b.render()
    assert "the CLI said sealed but the read-back disagrees" in b.summary
    assert "the witness holds no pin" in b.summary
    assert "sealed=true" in b.lines[0] and "-> 404 no pin" in b.lines[1]
    assert stub.pins == {}


def test_planted_failure_a_seal_that_succeeds_with_no_key_fails_a(tmp_path, stub):
    a = rc.check_a(_fake(tmp_path, stub, "lies-sealed"))
    assert a.status == "FAIL"
    assert "exit 0" in a.summary and "not false" in a.summary


def test_planted_failure_a_cli_that_reports_success_outside_the_fence_fails_c(tmp_path, stub):
    c, prefix = rc.check_c(_fake(tmp_path, stub, "lies-sealed"))
    assert c.status == "FAIL" and prefix is None
    assert "CLI exit 0" in c.summary and "not 403" in c.summary


def test_a_fails_when_the_house_is_not_empty(tmp_path, stub):
    run = _real(tmp_path, stub)
    (run.house.home / ".arcaeon").mkdir()
    (run.house.home / ".arcaeon" / "config").write_text("x", encoding="utf-8")
    a = rc.check_a(run)
    assert a.status == "FAIL" and "home held 1 file(s) before the run" in a.summary


def test_the_house_env_inherits_nothing(tmp_path, monkeypatch):
    for name in ("ARCAEON_KEY", "ARCAEON_WITNESS_URL", "PYTHONPATH", "PIP_INDEX_URL", "SOME_OTHER"):
        monkeypatch.setenv(name, "leak")
    house = rc.House.build(tmp_path / "h")
    env = rc.house_env(house)
    assert "leak" not in env.values()
    for name in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"):
        assert env[name] == str(house.home)
    assert house.home_files() == []
    run = rc.Run(cli=["x"], house=house, fixture=house.work / "f", witness_url="http://127.0.0.1:9",
                 key=None, stubbed=True, stub=None, extra_env={"ARCAEON_KEY": "planted"})
    seen = {}
    monkeypatch.setattr(rc, "_run", lambda cmd, env, cwd, timeout=0: seen.update(env) or None)
    run.seal(key=None, url="http://127.0.0.1:9", log=house.work / "a" / "l.jsonl")
    assert "ARCAEON_KEY" not in seen


def test_stub_speaks_the_witness_contract(stub):
    import urllib.request

    def post(body, key):
        req = urllib.request.Request(stub.url + "/api/pin", data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {key}",
                                              "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    assert post({"namespace": "rc-stub-x", "rows": 1, "chain": "a"}, "wrong")[0] == 401
    st, body = post({"namespace": "other", "rows": 1, "chain": "a"}, stub.key)
    assert st == 403 and body["error"] == 'this key may only pin namespaces starting with "rc-stub-"'
    assert post({"namespace": "rc-stub-x", "rows": 2, "chain": "b"}, stub.key)[0] == 201
    assert post({"namespace": "rc-stub-x", "rows": 1, "chain": "c"}, stub.key)[0] == 409
    assert rc.read_pin(stub.url, "rc-stub-x") == (200, stub.pins["rc-stub-x"])
    assert rc.read_pin(stub.url, "nothing-here") == (404, None)


def test_ledger_head_recomputes_and_catches_an_edit(tmp_path):
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from arcaeon.record.ledger import Ledger
    finally:
        sys.path.pop(0)
    path = tmp_path / "l.jsonl"
    led = Ledger(path)
    led.append({"op": "one", "artifact_digest": "x"})
    led.append({"op": "two", "artifact_digest": "y"})
    head = led.head()
    rows, chain, last, problem = rc.ledger_head(path)
    assert (rows, chain, problem) == (head.rows, head.chain, None)
    assert last["artifact_digest"] == "y"
    path.write_text(path.read_text(encoding="utf-8").replace('"one"', '"ONE"'), encoding="utf-8")
    assert rc.ledger_head(path)[3] == "line 1's chain does not recompute"


def test_publish_runs_the_release_check_after_the_venv_step_and_before_the_scan():
    publish = _load("publish_for_rc_test", ROOT / "tools" / "publish.py")
    names = [s.__name__ for s in publish.STEPS]
    assert names.index("step_venv") + 1 == names.index("step_release_check")
    assert names.index("step_release_check") + 1 == names.index("step_scan")
    assert publish.TOTAL == len(publish.STEPS) + 1


@pytest.mark.parametrize("stdout,code,ok", [
    ("PASS    A x\nSTUBBED B y\n          outcome: z\nSTUBBED C w\n", 0, True),
    ("PASS    A x\nFAIL    B the CLI said sealed but the read-back disagrees\nSTUBBED C w\n", 1, False),
    ("PASS    A x\nSTUBBED C w\n", 0, False),
])
def test_publish_step_reads_the_three_lines(tmp_path, stdout, code, ok):
    publish = _load("publish_for_rc_step", ROOT / "tools" / "publish.py")

    class P:
        returncode, stderr = code, ""

    P.stdout = stdout
    seen = {}
    publish._run = lambda cmd, **kw: seen.setdefault("cmd", [str(c) for c in cmd]) and P()

    class Ctx:
        version = "9.9.9"
        env_file = tmp_path / "no.env"
        main_artifacts = [tmp_path / "arcaeon-9.9.9-py3-none-any.whl"]

    if ok:
        line = publish.step_release_check(Ctx)
        assert line.startswith("release check from an empty house: A PASS, B STUBBED, C STUBBED")
        assert "STUBBED (local stub witness" in line
    else:
        with pytest.raises(publish.StepFailed):
            publish.step_release_check(Ctx)
    assert seen["cmd"][1].endswith("release_check.py") and "--wheel" in seen["cmd"]
