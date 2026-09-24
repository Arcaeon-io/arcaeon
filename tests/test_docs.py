"""The docs say what the code does.

- every verb has a section in docs/VERBS.md, and its usage block is the
  `usage:` text `arcaeon <verb> --help` prints today (tools/sync_verbs_usage.py
  regenerates them);
- the README's install line, extras and Python floor match pyproject.toml;
- every `$` line in the README's first-run section runs, in a temp dir, and
  prints the lines and exit code the README shows;
- the README makes none of the claims it must not make;
- MIGRATION.md and shims/README.md list the same 13 old names with the same
  imports, and MIGRATION's "exit code changed?" column agrees with
  arcaeon.verdict.LEGACY.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
README = (ROOT / "README.md").read_text(encoding="utf-8")
VERBS_MD = (ROOT / "docs" / "VERBS.md").read_text(encoding="utf-8")
MIGRATION = (ROOT / "MIGRATION.md").read_text(encoding="utf-8")
SHIMS_README = (ROOT / "shims" / "README.md").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

_spec = importlib.util.spec_from_file_location("sync_verbs_usage",
                                               ROOT / "tools" / "sync_verbs_usage.py")
sync = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync)

OLD_NAMES = ["arcaeon-ledger", "arcaeon-adapter", "arcaeon-receipt", "arcaeon-audit",
             "arcaeon-mcp-vet", "arcaeon-once", "arcaeon-compact", "arcaeon-continuity",
             "arcaeon-baseline", "arcaeon-dedup", "arcaeon-distill", "arcaeon-meter",
             "arcaeon-all"]


def _section(text: str, heading: str) -> str:
    """The body under a `## heading`, up to the next `## `."""
    m = re.search(r"^## " + re.escape(heading) + r"\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert m, f"no section '## {heading}'"
    return m.group(1)


# --- docs/VERBS.md -----------------------------------------------------------------

def test_every_verb_has_a_section_and_nothing_else():
    sections = re.findall(r"^## `([a-z]+)`\s*$", VERBS_MD, re.M)
    assert sorted(sections) == sorted(cli.VERBS)
    assert len(sections) == len(set(sections)), "a verb has two sections"


def test_sections_follow_the_help_order():
    sections = re.findall(r"^## `([a-z]+)`\s*$", VERBS_MD, re.M)
    assert sections == list(cli.VERBS)


def test_every_section_has_usage_exit_codes_and_an_example():
    heads = list(re.finditer(r"^## `([a-z]+)`\s*$", VERBS_MD, re.M))
    for n, h in enumerate(heads):
        end = heads[n + 1].start() if n + 1 < len(heads) else len(VERBS_MD)
        body = VERBS_MD[h.end():end]
        verb = h.group(1)
        assert "Answers:" in body, verb
        assert "**Usage**" in body, verb
        assert "**Exit codes:**" in body, verb
        assert f"$ arcaeon {verb}" in body or f"arcaeon {verb} " in body, verb


def _mcp_sdk() -> bool:
    return importlib.util.find_spec("mcp") is not None


@pytest.mark.parametrize("verb", list(cli.VERBS))
def test_usage_block_matches_help(verb):
    if verb == "mcp" and not _mcp_sdk():
        pytest.skip("`arcaeon mcp --help` needs the [mcp] extra installed")
    written = sync.doc_blocks(VERBS_MD).get(verb)
    assert written is not None, f"no usage block for {verb}"
    actual = sync.usage_block(verb)
    if actual is None:
        # a verb whose --help prints no usage: line says so in the doc; if the
        # help gains one, this fails and the doc is regenerated
        assert written == sync.NO_USAGE, verb
    else:
        assert written == actual, (
            f"docs/VERBS.md usage for {verb} is stale; run py tools/sync_verbs_usage.py")


# --- README: install, extras, floor -------------------------------------------------

def _pyproject_extras() -> set[str]:
    try:
        import tomllib
        return set(tomllib.loads(PYPROJECT)["project"]["optional-dependencies"])
    except ImportError:  # Python 3.10
        block = re.search(r"^\[project\.optional-dependencies\]\n(.*?)(?=^\[)", PYPROJECT,
                          re.M | re.S).group(1)
        return set(re.findall(r"^([a-z]+)\s*=", block, re.M))


def test_readme_install_line_and_floor_match_pyproject():
    install = _section(README, "Install")
    assert "pip install arcaeon\n" in install
    assert re.search(r'^name = "arcaeon"$', PYPROJECT, re.M)
    floor = re.search(r'^requires-python = ">=(\d+\.\d+)"$', PYPROJECT, re.M).group(1)
    assert f"Python {floor} or newer" in install
    assert re.search(r"^dependencies = \[\]$", PYPROJECT, re.M), "base install has deps"
    assert "zero dependencies" in install


def test_readme_extras_match_pyproject():
    install = _section(README, "Install")
    named = set(re.findall(r"arcaeon\[([a-z]+)\]", install))
    assert named == _pyproject_extras()


# --- README: the first run actually runs ------------------------------------------

def _first_run_steps():
    body = _section(README, "A 60-second first run")
    block = re.search(r"```console\n(.*?)```", body, re.S).group(1)
    steps = []
    for line in block.splitlines():
        if line.startswith("$ "):
            steps.append({"cmd": line[2:], "expect": [], "exit": 0})
        elif steps:
            m = re.fullmatch(r"\(exit (\d+)\)", line.strip())
            if m:
                steps[-1]["exit"] = int(m.group(1))
            elif line.strip() in ("", "...") or re.fullmatch(r"<[^>]*>", line.strip()):
                continue
            else:
                steps[-1]["expect"].append(line.strip())
    return steps


def test_first_run_shows_both_words():
    steps = _first_run_steps()
    shown = "\n".join(x for s in steps for x in s["expect"])
    assert '"verdict": "VERIFIED"' in shown and '"verdict": "BROKEN"' in shown
    assert [s["exit"] for s in steps if s["cmd"].startswith("arcaeon verify")] == [0, 1]


def test_first_run_commands_run_and_print_what_the_readme_says(tmp_path):
    steps = _first_run_steps()
    assert len(steps) >= 5
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    env.pop("ARCAEON_KEY", None)
    for step in steps:
        argv = shlex.split(step["cmd"])
        if argv[0] == "arcaeon":
            argv = [sys.executable, "-m", "arcaeon", *argv[1:]]
        elif argv[0] == "python":
            argv = [sys.executable, *argv[1:]]
        else:
            pytest.fail(f"first-run step is not arcaeon or python: {step['cmd']}")
        p = subprocess.run(argv, cwd=tmp_path, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        assert p.returncode == step["exit"], (step["cmd"], p.stdout, p.stderr)
        out_lines = {x.strip() for x in p.stdout.splitlines()}
        for want in step["expect"]:
            assert want in out_lines, (step["cmd"], want, p.stdout)


# --- README: what it must not say ------------------------------------------------

FORBIDDEN = ["multi-witness", "court", "regulator", "guarantee", "—"]


@pytest.mark.parametrize("phrase", FORBIDDEN)
def test_readme_has_no_forbidden_phrase(phrase):
    assert phrase.lower() not in README.lower(), phrase


def test_no_em_dash_in_the_new_docs():
    for name in ("docs/VERBS.md", "docs/PUBLISH_DRY_RUN.md"):
        assert "—" not in (ROOT / name).read_text(encoding="utf-8"), name


def test_readme_quotes_no_prices():
    assert not re.search(r"\$\s?\d", README), "prices live at arcaeon.io/pricing"
    assert "arcaeon.io/pricing" in README


def test_readme_points_at_the_other_docs():
    for target in ("docs/VERBS.md", "docs/DEAL.md", "MIGRATION.md", "shims/README.md",
                   "LICENSE"):
        assert f"]({target})" in README, target
        assert (ROOT / target).exists(), target
    assert "--legacy-exit" in README and "uvx arcaeon" in README and "ARCAEON_KEY" in README


def test_readme_exit_table_matches_verdict():
    table = _section(README, "Exit codes")
    rows = dict(re.findall(r"^\| (\d) \| ([^|]+)\|", table, re.M))
    assert set(rows) == {str(V.EXIT_GOOD), str(V.EXIT_BAD), str(V.EXIT_USAGE),
                         str(V.EXIT_COULD_NOT_LOOK)}
    for word, code in V.EXIT_BY_WORD.items():
        if word == V.COULD_NOT_LOOK_TOKEN:
            continue
        if word == V.NO_GRADEABLE_FILES:
            continue
        assert word in rows[str(code)], (word, code)


def test_readme_limits_carry_reconcile_limits_verbatim():
    from arcaeon.prove.reconcile import LIMITS
    limits = " ".join(_section(README, "Limits").split())
    for line in LIMITS:
        assert line in limits, line


# --- MIGRATION.md and shims/README.md agree ------------------------------------------

def _rows(text: str, first_col_prefix: str = "arcaeon-") -> dict[str, list[str]]:
    out = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and cells and cells[0].startswith(first_col_prefix):
            out[cells[0]] = cells
    return out


def _module(cell: str) -> str:
    m = re.search(r"`(?:import )?([a-z_.]+)`", cell)
    assert m, cell
    return m.group(1)


def _migration_rows():
    return _rows(_section(MIGRATION, "If you used the old packages"))


def test_migration_and_shims_list_the_same_13_names():
    mig, shim = _migration_rows(), _rows(SHIMS_README)
    assert sorted(mig) == sorted(OLD_NAMES)
    assert sorted(shim) == sorted(OLD_NAMES)
    assert sorted(p.name for p in (ROOT / "shims").iterdir() if p.is_dir()) == sorted(OLD_NAMES)


def test_migration_and_shims_agree_on_imports():
    mig, shim = _migration_rows(), _rows(SHIMS_README)
    for name in OLD_NAMES:
        # MIGRATION: name | old import | new import | ...; shims: name | ver | old | new | ...
        assert _module(mig[name][1]) == _module(shim[name][2]), name
        assert _module(mig[name][2]) == _module(shim[name][3]), name


def test_new_imports_in_migration_really_import():
    for name, cells in _migration_rows().items():
        importlib.import_module(_module(cells[2]))


#: old package -> the arcaeon verb whose exit codes moved, if any
_VERB_OF = {"arcaeon-receipt": "receipt", "arcaeon-audit": "audit", "arcaeon-mcp-vet": "vet"}


def test_migration_exit_column_agrees_with_verdict_legacy():
    for name, cells in _migration_rows().items():
        changed = cells[5].lower().startswith("yes")
        if name == "arcaeon-ledger":
            # reconcile's move lives in arcaeon.prove.reconcile, not LEGACY
            from arcaeon.prove.reconcile import EXIT_CODES, LEGACY_EXIT_CODES
            assert changed == (EXIT_CODES != LEGACY_EXIT_CODES), name
            continue
        verb = _VERB_OF.get(name)
        assert changed == (verb is not None and verb in V.LEGACY), name
