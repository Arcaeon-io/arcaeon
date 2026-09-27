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


# --- B041: STUBBED blocks when the paid path changed since the last release ------

import subprocess  # noqa: E402

CLI_V1 = '''def _pin(argv):
    local = "witness half"
    from arcaeon import remote
    return remote.pin()


def _seal(argv):
    return 1


def _credits(argv):
    return 2


def _pin_ns_from_key(fn):
    return 3


def _log(argv):
    return 4
'''


def _git(repo, *args):
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout.strip()


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    monkeypatch.delenv("ARCAEON_RC_PAID_BASE", raising=False)
    r = tmp_path / "repo"
    (r / "src" / "arcaeon" / "remote").mkdir(parents=True)
    (r / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0.1.0"\n', encoding="utf-8")
    (r / "src" / "arcaeon" / "cli.py").write_text(CLI_V1, encoding="utf-8")
    (r / "src" / "arcaeon" / "remote" / "witness.py").write_text("X = 1\n", encoding="utf-8")
    (r / "README.md").write_text("hi\n", encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    _git(r, "config", "core.autocrlf", "false")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "0.1.0: version bump")
    return r


def _edit(repo, rel, old, new, commit=True):
    p = repo / rel
    p.write_text(p.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    if commit:
        _git(repo, "commit", "-q", "-am", f"edit {rel}")


STUBBED = [rc.Check("A", "a", "PASS"), rc.Check("B", "b", "STUBBED"), rc.Check("C", "c", "STUBBED")]


def test_untouched_diff_does_not_block(repo):
    _edit(repo, "README.md", "hi", "hello")
    _edit(repo, "src/arcaeon/cli.py", "return 4", "return 44")          # not paid
    _edit(repo, "src/arcaeon/cli.py", 'local = "witness half"', 'local = "w"')  # _pin's local half
    changed, how = rc.paid_path_changes(repo)
    assert changed == [] and "version bump" in how and "no tags" in how
    assert rc.paid_path_gate(STUBBED, repo) is None


@pytest.mark.parametrize("rel,old,new,want", [
    ("src/arcaeon/remote/witness.py", "X = 1", "X = 2", "src/arcaeon/remote/witness.py"),
    ("src/arcaeon/cli.py", "return 1", "return 11", "cli._seal"),
    ("src/arcaeon/cli.py", "return 2", "return 22", "cli._credits"),
    ("src/arcaeon/cli.py", "return remote.pin()", "return remote.renew()", "cli._pin[remote]"),
    ("src/arcaeon/cli.py", "return 3", "return 33", "cli._pin_ns_from_key"),
])
def test_touched_paid_path_blocks_a_stubbed_run(repo, rel, old, new, want):
    _edit(repo, rel, old, new)
    changed, _ = rc.paid_path_changes(repo)
    assert changed == [want]
    line = rc.paid_path_gate(STUBBED, repo)
    assert line.startswith("BLOCKED paid path changed and not exercised: set ARCAEON_TEST_KEY")
    assert want in line


def test_uncommitted_and_new_remote_files_count(repo):
    (repo / "src" / "arcaeon" / "remote" / "new.py").write_text("Y = 1\n", encoding="utf-8")
    changed, _ = rc.paid_path_changes(repo)
    assert changed == ["src/arcaeon/remote/new.py"]
    (repo / "src" / "arcaeon" / "remote" / "new.py").unlink()
    _edit(repo, "src/arcaeon/cli.py", "return 1", "return 11", commit=False)
    assert rc.paid_path_changes(repo)[0] == ["cli._seal"]


def test_the_base_is_the_last_tag_when_there_is_one(repo):
    _edit(repo, "src/arcaeon/remote/witness.py", "X = 1", "X = 2")
    _git(repo, "tag", "v0.1.1")
    changed, how = rc.paid_path_changes(repo)
    assert (changed, how) == ([], "tag v0.1.1")
    _edit(repo, "src/arcaeon/cli.py", "return 2", "return 22")
    assert rc.paid_path_changes(repo)[0] == ["cli._credits"]


def test_the_base_moves_with_the_next_version_bump(repo):
    _edit(repo, "src/arcaeon/remote/witness.py", "X = 1", "X = 2")
    _edit(repo, "pyproject.toml", "0.1.0", "0.1.1")
    assert rc.paid_path_changes(repo)[0] == []


def test_a_real_key_run_or_a_fail_is_not_gated(repo):
    _edit(repo, "src/arcaeon/remote/witness.py", "X = 1", "X = 2")
    passed = [rc.Check("A", "a", "PASS"), rc.Check("B", "b", "PASS"), rc.Check("C", "c", "PASS")]
    assert rc.paid_path_gate(passed, repo) is None


def test_an_explicit_base_overrides_and_is_named(repo, monkeypatch, capsys):
    _edit(repo, "src/arcaeon/remote/witness.py", "X = 1", "X = 2")
    monkeypatch.setenv("ARCAEON_RC_PAID_BASE", "HEAD")
    assert rc.paid_path_changes(repo) == ([], "HEAD (ARCAEON_RC_PAID_BASE)")
    assert rc.paid_path_gate(STUBBED, repo) is None
    assert "paid path unchanged since HEAD (ARCAEON_RC_PAID_BASE)" in capsys.readouterr().out
    monkeypatch.setenv("ARCAEON_RC_PAID_BASE", "no-such-rev")
    assert "COULD NOT LOOK" in rc.paid_path_gate(STUBBED, repo)


def test_could_not_look_blocks(tmp_path, monkeypatch):
    monkeypatch.delenv("ARCAEON_RC_PAID_BASE", raising=False)
    line = rc.paid_path_gate(STUBBED, tmp_path)   # not a git repo
    assert line.startswith("BLOCKED paid path changed and not exercised: set ARCAEON_TEST_KEY")
    assert "COULD NOT LOOK" in line


def test_publish_names_the_blocked_line(tmp_path):
    publish = _load("publish_for_rc_block", ROOT / "tools" / "publish.py")

    class P:
        returncode, stderr = 1, ""
        stdout = ("PASS    A x\nSTUBBED B y\nSTUBBED C w\n"
                  "BLOCKED paid path changed and not exercised: set ARCAEON_TEST_KEY (since tag v1: cli._seal)\n")

    publish._run = lambda cmd, **kw: P()

    class Ctx:
        version = "9.9.9"
        env_file = tmp_path / "no.env"
        main_artifacts = [tmp_path / "arcaeon-9.9.9-py3-none-any.whl"]

    with pytest.raises(publish.StepFailed) as e:
        publish.step_release_check(Ctx)
    assert "set ARCAEON_TEST_KEY" in str(e.value)


# --- B048: the site's products.yaml version is a WARN, never a FAIL ---------------

PRODUCTS = """schema: arcaeon-products/v1
site:
  name: Arcaeon
  version: 9.9.9
products:
- id: verified-snapshot
  version: 0.1.9
- id: arcaeon
  name: arcaeon
  version: {v}
  status: shipped
- id: cite
  version: null
"""


def _site(tmp_path, v):
    root = tmp_path / "site"
    root.mkdir()
    (root / "products.yaml").write_text(PRODUCTS.format(v=v), encoding="utf-8")
    return root


def test_site_version_reads_the_arcaeon_entry_only():
    assert rc.products_yaml_version(PRODUCTS.format(v="0.9.1")) == "0.9.1"
    assert rc.products_yaml_version(PRODUCTS.format(v="'0.9.2'")) == "0.9.2"
    assert rc.products_yaml_version("products:\n- id: other\n  version: 1.0\n") is None


def test_site_version_match_is_ok(tmp_path):
    line = rc.site_version_line("0.9.1", _site(tmp_path, "0.9.1"))
    assert line.startswith("OK ") and "both say 0.9.1" in line


def test_site_version_mismatch_warns_not_fails(tmp_path):
    line = rc.site_version_line("0.9.2", _site(tmp_path, "0.9.1"))
    assert line.startswith("WARN ") and "products.yaml says 0.9.1" in line
    assert "pyproject.toml says 0.9.2" in line and "FAIL" not in line


def test_site_version_absent_is_could_not_look(tmp_path, monkeypatch):
    assert rc.site_version_line("0.9.1", tmp_path / "nowhere").startswith("COULD NOT LOOK site version")
    monkeypatch.setenv("ARCAEON_SITE_ROOT", str(tmp_path / "nowhere"))
    assert rc.site_version_line("0.9.1").startswith("COULD NOT LOOK site version")
    monkeypatch.setattr(rc, "site_root", lambda: None)
    line = rc.site_version_line("0.9.1")
    assert line.startswith("COULD NOT LOOK site version: no site checkout") and "not a fail" in line


def test_site_version_line_does_not_trip_publish_step_parsing(tmp_path):
    publish = _load("publish_for_site_version", ROOT / "tools" / "publish.py")
    line = rc.site_version_line("0.9.2", _site(tmp_path, "0.9.1"))
    assert publish.RC_LINE.match(line) is None


# --- K001: every registered verb built, every VERBS.md section written ----------

_FAKE_CLI = '''
VERBS = {"log": ("record", "x"), "serve": ("serve", "y")}
LAZY_VERBS = {
    "serve": ("arcaeon.serve.cli", "K004"),
}
'''


def _verbs_root(tmp_path, *, built: bool, doc: str):
    (tmp_path / "src" / "arcaeon").mkdir(parents=True)
    (tmp_path / "src" / "arcaeon" / "cli.py").write_text(_FAKE_CLI, encoding="utf-8")
    if built:
        (tmp_path / "src" / "arcaeon" / "serve").mkdir()
        (tmp_path / "src" / "arcaeon" / "serve" / "cli.py").write_text(
            "def main(argv):\n    return 0\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "VERBS.md").write_text(doc, encoding="utf-8")
    return tmp_path


def test_verbs_ok_when_every_module_exists_and_no_marker_is_left(tmp_path):
    root = _verbs_root(tmp_path, built=True, doc="## `log`\n\ntext\n\n## `serve`\n\ntext\n")
    assert rc.verbs_problems(root) == []
    assert rc.verbs_line([]).startswith("OK      verbs:")


def test_verbs_fail_on_a_missing_module_naming_it(tmp_path):
    root = _verbs_root(tmp_path, built=False, doc="## `serve`\n\ntext\n")
    probs = rc.verbs_problems(root)
    assert len(probs) == 1 and "serve (arcaeon.serve.cli)" in probs[0]
    assert rc.verbs_line(probs).startswith("FAIL    verbs:")


def test_verbs_fail_on_a_todo_marker_naming_it(tmp_path):
    root = _verbs_root(tmp_path, built=True, doc="## `serve`\n\nTODO(K004)\n")
    probs = rc.verbs_problems(root)
    assert probs == ["docs/VERBS.md still holds TODO(K004)"]


def test_verbs_unreadable_cli_is_a_problem_not_a_pass(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "VERBS.md").write_text("", encoding="utf-8")
    probs = rc.verbs_problems(tmp_path)
    assert probs and "cannot read" in probs[0]


def test_verbs_the_real_checkout_names_every_unbuilt_plugin_verb():
    """The real repo: each LAZY_VERBS module that is absent is named, and each
    TODO section left in VERBS.md is named; nothing is quietly passed."""
    table = rc.lazy_verb_modules((ROOT / "src" / "arcaeon" / "cli.py").read_text(encoding="utf-8"))
    assert table and "serve" in table
    probs = " ".join(rc.verbs_problems(ROOT))
    for verb, mod in table.items():
        if rc._module_file(ROOT, mod) is None:
            assert f"{verb} ({mod})" in probs
    doc = (ROOT / "docs" / "VERBS.md").read_text(encoding="utf-8")
    if "TODO(K" in doc:
        assert "still holds" in probs


def test_main_exits_1_when_a_verb_is_unbuilt(monkeypatch, capsys, tmp_path):
    """The verbs FAIL line decides the exit even when A, B and C pass."""
    monkeypatch.setattr(rc, "verbs_problems", lambda root=None: ["registered verb(s) with no module: serve"])
    monkeypatch.setattr(rc, "site_version_line", lambda v, root=None: "OK      site version: stub")
    ok = rc.Check("A", "stub", "PASS", "ok")
    monkeypatch.setattr(rc, "run_checks", lambda run: [ok, ok, ok])
    monkeypatch.setattr(rc, "paid_path_gate", lambda checks, cwd=None: None)
    monkeypatch.setattr(rc, "install", lambda house, **kw: Path(sys.executable))
    wheel = tmp_path / "x.whl"
    wheel.write_bytes(b"")
    assert rc.main(["--stub", "--wheel", str(wheel)]) == 1
    assert "FAIL    verbs: registered verb(s) with no module: serve" in capsys.readouterr().out
