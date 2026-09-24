"""The 13 old PyPI names, as shims (shims/<old-name>/).

Nothing is installed. Each check runs in a SUBPROCESS with `shims/<name>` and
`src` first on the path, because this process blocks the old module names
(conftest.py) and this machine still has the old packages installed: every
check also asserts the module it got is the shim's file, not an old install.

What is held here, per shim:
  * `import <old_module>` works and yields every old public name MIGRATION.md
    lists for it (plus the old package's own `__all__`, which the shim keeps),
    each one the SAME object as in its new home;
  * the DeprecationWarning fires exactly once and names the new module;
  * every old submodule path resolves to the new module itself;
  * every old console script answers `--help` with exit 0, and one real
    command per shim returns the exit code the OLD package returned for that
    outcome (arcaeon.verdict.LEGACY says where the new code differs);
  * the shim's pyproject depends on `arcaeon` and nothing else.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover  (3.10)
    tomllib = None

from arcaeon import verdict as V

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SHIMS = ROOT / "shims"

# old PyPI name -> (old import name, new module)
TABLE = {
    "arcaeon-ledger": ("arcaeon_ledger", "arcaeon.record.ledger"),
    "arcaeon-adapter": ("arcaeon_adapter", "arcaeon.record.adapter"),
    "arcaeon-receipt": ("arcaeon_receipt", "arcaeon.record.receipt"),
    "arcaeon-audit": ("arcaeon_audit", "arcaeon.prove.audit"),
    "arcaeon-mcp-vet": ("mcp_vet", "arcaeon.prove.vet"),
    "arcaeon-once": ("arcaeon_once", "arcaeon.record.once"),
    "arcaeon-compact": ("arcaeon_compact", "arcaeon.prove.compact"),
    "arcaeon-continuity": ("arcaeon_continuity", "arcaeon.prove.continuity"),
    "arcaeon-baseline": ("arcaeon_baseline", "arcaeon.prove.baseline"),
    "arcaeon-dedup": ("arcaeon_dedup", "arcaeon.save.dedup"),
    "arcaeon-distill": ("arcaeon_distill", "arcaeon.save.distill"),
    "arcaeon-meter": ("arcaeon_meter", "arcaeon.save.meter"),
    "arcaeon-all": ("arcaeon_all", "arcaeon"),
}
NAMES = sorted(TABLE)


def _pyproject(name: str) -> dict:
    text = (SHIMS / name / "pyproject.toml").read_text(encoding="utf-8")
    if tomllib is None:  # pragma: no cover
        pytest.skip("tomllib needs Python 3.11+")
    return tomllib.loads(text)


def _scripts() -> list[tuple[str, str, str]]:
    out = []
    for name in NAMES:
        for script, target in _pyproject(name)["project"].get("scripts", {}).items():
            out.append((name, script, target))
    return out


def _migration_public_names(old: str) -> list[str]:
    """The public def/class names MIGRATION.md lists for the old top-level module."""
    md = (ROOT / "MIGRATION.md").read_text(encoding="utf-8")
    for line in md.splitlines():
        m = re.match(r"\| `([a-z_\.]+)` \| `([a-z_\.]+)` \| (.*) \|$", line)
        if m and m.group(1) == old:
            cells = re.sub(r" -> `[^`]*`", "", m.group(3))
            return [n for n in re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", cells)
                    if not n.startswith("_")]
    if old == "arcaeon_all":      # metadata-only package, not in the port tables
        return ["COMPONENTS", "versions"]
    raise AssertionError(f"{old} has no row in MIGRATION.md")


def _run(name: str, code: str, cwd: Path | None = None, timeout: int = 180):
    """Run `code` in a fresh interpreter that sees only this shim and src/."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(SHIMS / name), str(SRC)])
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("ARCAEON_KEY", None)          # nothing here may reach the hosted witness
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=cwd, env=env,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def _json_tail(proc) -> dict:
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


# --- layout ----------------------------------------------------------------------

def test_the_thirteen_old_names_each_have_a_shim():
    assert sorted(p.name for p in SHIMS.iterdir() if p.is_dir()) == NAMES


@pytest.mark.parametrize("name", NAMES)
def test_pyproject_depends_on_arcaeon_and_nothing_else(name):
    proj = _pyproject(name)["project"]
    want = "arcaeon[all]>=0.9,<1" if name == "arcaeon-all" else "arcaeon>=0.9,<1"
    assert proj["dependencies"] == [want]
    assert "optional-dependencies" not in proj
    assert proj["name"] == name
    assert proj["requires-python"] == ">=3.10"
    assert re.fullmatch(r"\d+\.\d+\.\d+", proj["version"])


@pytest.mark.parametrize("name", NAMES)
def test_a_shim_ships_only_its_compat_module(name):
    old, _new = TABLE[name]
    def built(p):   # a local `pip wheel` leaves these (git-ignored), and they never ship
        return any(part in ("__pycache__", "build") or part.endswith(".egg-info")
                   for part in p.relative_to(SHIMS / name).parts)
    files = sorted(p.relative_to(SHIMS / name).as_posix() for p in (SHIMS / name).rglob("*")
                   if p.is_file() and not built(p))
    assert files == [f"{old}/__init__.py", "pyproject.toml"]
    assert _pyproject(name)["tool"]["setuptools"]["packages"] == [old]


def test_no_compat_module_lives_inside_arcaeon():
    old_names = {old for old, _ in TABLE.values()}
    inside = [p for p in SRC.rglob("*") if p.stem in old_names or p.name in old_names]
    assert inside == []


def test_arcaeon_itself_no_longer_depends_on_an_old_name():
    """The connector-era `arcaeon` hard-depended on arcaeon-ledger and
    arcaeon-mcp-vet; with the shims depending on arcaeon, that would be a cycle."""
    if tomllib is None:  # pragma: no cover
        pytest.skip("tomllib needs Python 3.11+")
    proj = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    reqs = list(proj.get("dependencies", []))
    for extra in proj.get("optional-dependencies", {}).values():
        reqs += extra
    bad = [r for r in reqs if re.match(r"(arcaeon[-_]|mcp[-_]vet)", r)]
    assert bad == []


# --- the import path ---------------------------------------------------------------

@pytest.mark.parametrize("name", NAMES)
def test_old_import_yields_every_old_public_name(name):
    old, new = TABLE[name]
    expected = sorted(set(_migration_public_names(old)) | {"__version__"})
    proc = _run(name, f"""
        import importlib, json, warnings
        warnings.simplefilter("ignore", DeprecationWarning)
        import {old} as shim
        target = importlib.import_module("{new}")
        want = {expected!r} + list(getattr(shim, "__all__", []))
        missing = [n for n in want if not hasattr(shim, n)]
        # the same object as its new home (arcaeon-all is a marker: it has its own names)
        moved = [n for n in want if "{old}" != "arcaeon_all" and hasattr(shim, n)
                 and n != "__version__" and getattr(shim, n) is not getattr(target, n, None)]
        star = {{}}
        exec("from {old} import *", star)
        print(json.dumps({{"file": shim.__file__, "arcaeon": importlib.import_module("arcaeon").__file__,
                          "missing": missing, "moved": moved,
                          "star_missing": [n for n in getattr(shim, "__all__", []) if n not in star],
                          "count": len(set(want))}}))
    """)
    out = _json_tail(proc)
    assert Path(out["file"]).resolve().is_relative_to((SHIMS / name).resolve()), out["file"]
    assert Path(out["arcaeon"]).resolve().is_relative_to(SRC.resolve()), out["arcaeon"]
    assert out["missing"] == []
    assert out["moved"] == []
    assert out["star_missing"] == []
    assert out["count"] >= len(expected)


@pytest.mark.parametrize("name", NAMES)
def test_deprecation_warning_fires_once_and_names_the_new_module(name):
    old, new = TABLE[name]
    proc = _run(name, f"""
        import json, warnings
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            import {old}
            import {old}          # a second import is the cached module: no second warning
        mine = [str(w.message) for w in caught
                if issubclass(w.category, DeprecationWarning) and "{old}" in str(w.message)]
        print(json.dumps(mine))
    """)
    assert proc.returncode == 0, proc.stderr[-2000:]
    mine = json.loads(proc.stdout.strip().splitlines()[-1])
    assert len(mine) == 1, mine
    assert f"import {new} instead" in mine[0]
    assert "\n" not in mine[0]


@pytest.mark.parametrize("name", [n for n in NAMES if n != "arcaeon-all"])
def test_every_old_submodule_is_the_new_module(name):
    old, _new = TABLE[name]
    proc = _run(name, f"""
        import importlib, json, warnings
        warnings.simplefilter("ignore", DeprecationWarning)
        import {old}
        wrong, skipped = [], []
        for old_name, new_name in {old}._SUBMODULES.items():
            try:
                target = importlib.import_module(new_name)
            except ImportError as e:      # an optional extra (mcp, tree_sitter) not installed
                skipped.append([old_name, str(e)])
                continue
            if importlib.import_module(old_name) is not target:
                wrong.append(old_name)
        print(json.dumps({{"n": len({old}._SUBMODULES), "wrong": wrong, "skipped": skipped}}))
    """)
    out = _json_tail(proc)
    assert out["wrong"] == []
    # a skip is only ever a missing optional extra, never a missing moved module
    assert all("arcaeon" not in reason for _, reason in out["skipped"]), out["skipped"]
    assert len(out["skipped"]) < out["n"] or out["n"] == 0


def test_python_dash_m_runs_an_old_main_module():
    proc = _run("arcaeon-meter", "import runpy, sys; sys.argv = ['arcaeon_meter', '--help']; "
                                 "runpy.run_module('arcaeon_meter', run_name='__main__')")
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "usage:" in proc.stdout


# --- the old console scripts --------------------------------------------------------

def _script(name: str, target: str, args: list[str], cwd: Path | None = None):
    mod, func = target.split(":")
    return _run(name, f"""
        import sys, warnings
        warnings.simplefilter("ignore", DeprecationWarning)
        sys.argv = ["script", *{args!r}]
        from {mod} import {func}
        sys.exit({func}())
    """, cwd=cwd)


def test_each_old_console_script_is_kept():
    assert sorted(s for _, s, _ in _scripts()) == sorted([
        "arcaeon-ledger", "arcaeon-adapter", "arcaeon-adapter-selftest", "arcaeon-receipt",
        "arcaeon-audit", "mcp-vet", "arcaeon-once", "arcaeon-baseline", "arcaeon-meter"])


@pytest.mark.parametrize("name,script,target", _scripts(), ids=[s for _, s, _ in _scripts()])
def test_old_console_script_help_exits_0(name, script, target, tmp_path):
    proc = _script(name, target, ["--help"], cwd=tmp_path)
    assert proc.returncode == 0, (proc.stdout[-1000:], proc.stderr[-1000:])
    assert proc.stdout.strip()


def _target(name, script):
    return _pyproject(name)["project"]["scripts"][script]


def _arcaeon(args, cwd):
    """The NEW front door, for contrast: `arcaeon <verb>` without --legacy-exit."""
    env = dict(os.environ, PYTHONPATH=str(SRC))
    env.pop("ARCAEON_KEY", None)
    return subprocess.run([sys.executable, "-m", "arcaeon.cli", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def test_ledger_append_verify_tamper_reconcile(tmp_path):
    t = _target("arcaeon-ledger", "arcaeon-ledger")
    log = tmp_path / "agent.log.jsonl"
    assert _script("arcaeon-ledger", t, ["append", str(log), '{"tool": "search", "ok": true}'],
                   tmp_path).returncode == 0
    assert _script("arcaeon-ledger", t, ["append", str(log), '{"tool": "fetch", "ok": true}'],
                   tmp_path).returncode == 0
    ok = _script("arcaeon-ledger", t, ["verify", str(log)], tmp_path)
    assert ok.returncode == 0, ok.stdout
    log.write_text(log.read_text(encoding="utf-8").replace("search", "SEARCH"), encoding="utf-8")
    assert _script("arcaeon-ledger", t, ["verify", str(log)], tmp_path).returncode == 1
    # COULD NOT LOOK: the old tool said 2, the one table says 3.
    old = _script("arcaeon-ledger", t, ["reconcile", "nope_a.jsonl", "nope_b.jsonl"], tmp_path)
    assert old.returncode == 2, old.stdout
    assert _arcaeon(["reconcile", "nope_a.jsonl", "nope_b.jsonl"], tmp_path).returncode == \
        V.EXIT_COULD_NOT_LOOK


# (shim, script, args, files to write first, the OLD exit code, arcaeon verb, subcommand)
LEGACY_CASES = [
    # a prechain row: the chain cannot speak for it. Old arcaeon-audit: 2.
    ("arcaeon-audit", "arcaeon-audit", ["verify", "pre.jsonl"], {"pre.jsonl": '{"a": 1}\n'},
     2, "audit", "verify"),
    # a receipt whose body does not verify. Old arcaeon-receipt: 2.
    ("arcaeon-receipt", "arcaeon-receipt", ["verify", "r.json"], {"r.json": "{}"},
     2, "receipt", "verify"),
    # a probe with no server command: could not connect. Old mcp-vet: 2.
    ("arcaeon-mcp-vet", "mcp-vet", ["probe"], {}, 2, "vet", "probe"),
]


@pytest.mark.parametrize("name,script,args,files,old_code,verb,sub", LEGACY_CASES,
                         ids=[c[0] for c in LEGACY_CASES])
def test_old_script_keeps_the_old_exit_code_where_the_table_changed_it(
        name, script, args, files, old_code, verb, sub, tmp_path):
    for fn, body in files.items():
        (tmp_path / fn).write_text(body, encoding="utf-8")
    proc = _script(name, _target(name, script), args, tmp_path)
    assert proc.returncode == old_code, (proc.stdout[-1500:], proc.stderr[-1500:])
    new_code = V.unify(verb, old_code, sub)
    assert new_code != old_code, "the LEGACY table must say this code changed"
    assert _arcaeon([verb, *args], tmp_path).returncode == new_code


# codes these tools never changed: the old script and the new verb agree.
SAME_CASES = [
    ("arcaeon-adapter", "arcaeon-adapter-selftest", [], 0),
    ("arcaeon-once", "arcaeon-once", ["receipt", "ops.log.jsonl", "refund:pi_1"], 1),
    ("arcaeon-baseline", "arcaeon-baseline", ["selftest"], 0),
    ("arcaeon-meter", "arcaeon-meter", ["keys", "list", "--keys", "keys.json"], 0),
]


@pytest.mark.parametrize("name,script,args,code", SAME_CASES, ids=[c[0] for c in SAME_CASES])
def test_old_script_runs_a_real_command(name, script, args, code, tmp_path):
    proc = _script(name, _target(name, script), args, tmp_path)
    assert proc.returncode == code, (proc.stdout[-1500:], proc.stderr[-1500:])


# shims whose old package had no console script: one real call through the old import.
LIBRARY_CASES = {
    "arcaeon-compact": "from arcaeon_compact import verify_receipt\n"
                       "assert verify_receipt({}).get('ok') is not True",
    "arcaeon-continuity": "from arcaeon_continuity import digest_json\n"
                          "from arcaeon.record.row import digest_json as d\n"
                          "assert digest_json({'a': 1}) == d({'a': 1})",
    "arcaeon-dedup": "from arcaeon_dedup import dedupe\n"
                     "kept, rep = dedupe(['the same line of text', 'the same line of text', 'other'])\n"
                     "assert kept == ['the same line of text', 'other'] and rep.removed == 1",
    "arcaeon-distill": "from arcaeon_distill import distill\n"
                       "text = '. '.join(f'Sentence {i} says something new' for i in range(400))\n"
                       "r = distill(text, budget=50)\n"
                       "assert r.truncated is True and r.est_tokens_after <= 50",
    "arcaeon-all": "import arcaeon_all\nassert arcaeon_all.versions() == {'arcaeon': '0.9.0'}",
}


@pytest.mark.parametrize("name", sorted(LIBRARY_CASES))
def test_shim_without_a_script_runs_a_real_call(name):
    proc = _run(name, "import warnings\nwarnings.simplefilter('ignore', DeprecationWarning)\n"
                + LIBRARY_CASES[name])
    assert proc.returncode == 0, proc.stderr[-2000:]
