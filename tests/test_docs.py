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

#: A section registered ahead of its code (K001): the marker and nothing else.
_TODO_BODY = re.compile(r"\s*TODO\(K\d+\)\s*")


def test_every_verb_has_a_section_and_nothing_else():
    sections = re.findall(r"^## `([a-z][a-z-]*)`\s*$", VERBS_MD, re.M)
    assert sorted(sections) == sorted(cli.VERBS)
    assert len(sections) == len(set(sections)), "a verb has two sections"


def test_every_verb_in_help_text_has_a_heading():
    listed = re.findall(r"^  ([a-z][a-z-]*) +\S", cli.help_text(), re.M)
    assert listed, "help_text() lists no verbs"
    headings = set(re.findall(r"^## `([a-z][a-z-]*)`\s*$", VERBS_MD, re.M))
    missing = [v for v in listed if v not in headings]
    assert not missing, f"verbs in `arcaeon --help` with no docs/VERBS.md heading: {missing}"


def test_sections_follow_the_help_order():
    sections = re.findall(r"^## `([a-z][a-z-]*)`\s*$", VERBS_MD, re.M)
    assert sections == list(cli.VERBS)


def test_every_section_has_usage_exit_codes_and_an_example():
    heads = list(re.finditer(r"^## `([a-z][a-z-]*)`\s*$", VERBS_MD, re.M))
    for n, h in enumerate(heads):
        end = heads[n + 1].start() if n + 1 < len(heads) else len(VERBS_MD)
        body = VERBS_MD[h.end():end]
        verb = h.group(1)
        if _TODO_BODY.fullmatch(body):
            # registered ahead of its code (K001): the section is its TODO
            # marker alone until the item that builds the verb writes it;
            # tools/release_check.py fails while any marker is left
            assert verb in cli.LAZY_VERBS, f"{verb}: only a K001 verb may be a TODO section"
            continue
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
    if _TODO_BODY.fullmatch(_section(VERBS_MD, f"`{verb}`")):
        pytest.skip(f"docs/VERBS.md section for {verb} is still its TODO marker")
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
    for name in ("docs/VERBS.md", "docs/PUBLISH_DRY_RUN.md", "docs/WORDS.md"):
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


# --- docs/WORDS.md -------------------------------------------------------------------

WORDS_MD = (ROOT / "docs" / "WORDS.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("word", list(V.WORDS))
def test_every_verdict_word_is_explained_in_words_md(word):
    assert f"**{word}.**" in WORDS_MD, word


@pytest.mark.parametrize("reason", list(V.REASON_WORDS))
def test_every_reason_word_has_a_line_in_words_md(reason):
    assert re.search(r"^- `" + re.escape(reason) + r"`: \S", WORDS_MD, re.M), reason


def test_readme_links_words_md():
    assert "](docs/WORDS.md)" in README


# --- README: honest limits -----------------------------------------------------------

_NEGATIONS = ("not ", "never ", "no ", "nor ", "isn't ", "is not ")


@pytest.mark.parametrize("phrase", ["tamper-proof", "independent witnesses",
                                    "independent witness", "outside our control"])
def test_readme_overclaims_appear_only_in_a_negation(phrase):
    low = README.lower()
    for m in re.finditer(re.escape(phrase), low):
        before = low[max(0, m.start() - 40):m.start()]
        assert any(n in before for n in _NEGATIONS), (phrase, README[m.start() - 40:m.end()])


def test_readme_honest_limits_block():
    limits = " ".join(_section(README, "Limits").split())
    for must in ("Tamper-evident, not tamper-proof", "One witness, and we operate it",
                 "a clock, not a party", "custody record"):
        assert must in limits, must


# --- docs/SECOND_READER.md (K045) ------------------------------------------------------

SECOND_READER = (ROOT / "docs" / "SECOND_READER.md").read_text(encoding="utf-8")


def _console_steps(text: str) -> list[dict]:
    """Every `$` line of every ```console block, in order, with the lines and
    exit code shown under it (`<...>` lines vary and are skipped)."""
    steps: list[dict] = []
    for block in re.findall(r"```console\n(.*?)```", text, re.S):
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


def test_second_reader_examples_run_and_print_what_the_doc_says(tmp_path):
    steps = _console_steps(SECOND_READER)
    assert len(steps) >= 8
    assert any("second-read compare" in s["cmd"] for s in steps)
    assert any("second-read run" in s["cmd"] and "--send" not in s["cmd"] for s in steps)
    assert not any("--send" in s["cmd"] for s in steps), "doc examples never send a claim"
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    for name in ("ARCAEON_KEY", "ARCAEON_WITNESS_URL", "ARCAEON_WITNESS_KEY"):
        env.pop(name, None)
    for step in steps:
        argv = shlex.split(step["cmd"])
        if argv[0] == "arcaeon":
            argv = [sys.executable, "-m", "arcaeon", *argv[1:]]
        elif argv[0] == "python":
            argv = [sys.executable, *argv[1:]]
        else:
            pytest.fail(f"SECOND_READER step is not arcaeon or python: {step['cmd']}")
        p = subprocess.run(argv, cwd=tmp_path, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        assert p.returncode == step["exit"], (step["cmd"], p.stdout, p.stderr)
        out_lines = {x.strip() for x in p.stdout.splitlines()}
        for want in step["expect"]:
            assert want in out_lines, (step["cmd"], want, p.stdout)


def test_second_reader_says_what_it_does_not_show():
    low = " ".join(SECOND_READER.split()).lower()
    for must in ("whether a claim holds", "one family", "one vendor",
                 "two readers agree on more than nine of ten rows under a sentence a third "
                 "stranger then reads the other way", "np-12 is wrong", "sending a claim is a "
                 "disclosure", "two integers"):
        assert must in low, must
    assert "## What it shows" in SECOND_READER and "## What it does not show" in SECOND_READER


def test_second_reader_quotes_np12_loss_condition_verbatim():
    quoted = ("two readers agree on more than nine of ten rows under a sentence a third "
              "stranger then reads the other way. If that happens, the two-of-two bar was "
              "measuring the readers' shared habits, not the sentence, and NP-12 is wrong.")
    assert quoted in " ".join(SECOND_READER.split())


@pytest.mark.parametrize("phrase", ["tamper-proof", "independent", "truth", "is true",
                                    "compliant", "guarantee", "\u2014", "\u2013"])
def test_second_reader_makes_no_overclaim(phrase):
    assert phrase not in SECOND_READER.lower(), phrase


# --- docs/MANDATE_GATE.md: every example runs (K079) ----------------------------------

MANDATE_MD = (ROOT / "docs" / "MANDATE_GATE.md").read_text(encoding="utf-8")


def _fenced(text: str, lang: str) -> list[str]:
    return re.findall(r"^```" + lang + r"\n(.*?)^```", text, re.S | re.M)


def _mandate_example(tmp_path) -> Path:
    """The doc's first JSON block, saved as mandate.json, as the doc says."""
    p = tmp_path / "mandate.json"
    p.write_text(_fenced(MANDATE_MD, "json")[0], encoding="utf-8")
    return p


def _mandate_steps():
    steps = []
    for block in _fenced(MANDATE_MD, "console"):
        for line in block.splitlines():
            if line.startswith("$ "):
                steps.append({"cmd": line[2:], "out": [], "exit": 0})
            elif steps:
                m = re.fullmatch(r"\(exit (\d+)\)", line.strip())
                if m:
                    steps[-1]["exit"] = int(m.group(1))
                else:
                    steps[-1]["out"].append(line)
    return steps


def test_mandate_doc_has_no_em_or_en_dash():
    assert "—" not in MANDATE_MD and "–" not in MANDATE_MD


def test_every_mandate_json_block_lints_valid():
    from arcaeon.record import mandate_cli
    import json
    blocks = _fenced(MANDATE_MD, "json")
    assert len(blocks) >= 2
    for b in blocks:
        res = mandate_cli.lint(json.loads(b))
        assert res["valid"], (b, res["problems"])


def test_mandate_doc_console_examples_print_what_the_doc_says(tmp_path, monkeypatch, capsys):
    steps = _mandate_steps()
    assert {s["exit"] for s in steps} == {0, 1, 3}, steps
    assert any(s["cmd"].startswith("arcaeon mandate lint") for s in steps)
    assert any(s["cmd"].startswith("arcaeon mandate explain") for s in steps)
    _mandate_example(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arc_home"))
    for step in steps:
        argv = shlex.split(step["cmd"])
        assert argv[0] == "arcaeon", step["cmd"]
        rc = cli.main(argv[1:])
        got = capsys.readouterr()
        assert rc == step["exit"], (step["cmd"], got.out, got.err)
        assert (got.out + got.err).splitlines() == step["out"], (step["cmd"], got.out, got.err)


def _mandate_request(lang: str) -> tuple[str, dict]:
    import json
    (block,) = _fenced(MANDATE_MD, lang)
    first, body = block.strip().split("\n", 1)
    return first.strip(), json.loads(body)


def test_mandate_doc_http_example_answers_what_the_doc_says(tmp_path, monkeypatch):
    from arcaeon.serve import h_mandate
    _mandate_example(tmp_path)
    monkeypatch.chdir(tmp_path)
    route, body = _mandate_request("http")
    assert route == "POST /v1/mandate/check"
    res = h_mandate.check(body)
    assert (res["verdict"], res["rule"], res["exit"]) == ("outside", "forbidden_acts", 1)
    assert '`"verdict": "outside"`, `"rule": "forbidden_acts"`, `"exit": 1`' in MANDATE_MD


def test_mandate_doc_mcp_example_answers_what_the_doc_says(tmp_path, monkeypatch):
    from arcaeon.mcp import server
    _mandate_example(tmp_path)
    monkeypatch.chdir(tmp_path)
    tool, args = _mandate_request("mcp")
    assert tool == "mandate_check" and tool in server.ALL_TOOLS
    res = server._mandate_check(args)
    assert (res["verdict"], res["rule"], res["exit"]) == ("outside", "forbidden_acts", 1)


def test_mandate_doc_names_every_surface_and_the_enforce_warning():
    for must in ("--http-forward", "arcaeon.record.receipt.call_proxy", "--mandate-log",
                 "spend_cap.total", "mandate_cap_exceeded", "mandate_loaded",
                 "mandate_changed", "Before you turn on `--mandate-enforce`",
                 "Enforce stops your agent", "mandate_sessions.jsonl",
                 "tests/test_mandate_default_record_only.py"):
        assert must in MANDATE_MD, must


# --- docs/ADAPTERS.md: every example runs against the fake frameworks (K092) ---------

ADAPTERS_MD = (ROOT / "docs" / "ADAPTERS.md").read_text(encoding="utf-8")

#: Section heading -> the adapter module its example imports.
_ADAPTER_SECTIONS = {
    "OpenAI Agents SDK": "arcaeon.adapters.openai_agents",
    "LangChain and LangGraph": "arcaeon.adapters.langchain",
    "LlamaIndex": "arcaeon.adapters.llamaindex",
    "CrewAI": "arcaeon.adapters.crewai",
    "AutoGen": "arcaeon.adapters.autogen",
}


def _fake_frameworks() -> dict:
    """Stand-ins for the five frameworks: each class takes what the adapter
    hands it and calls back the way the framework does. Never the real SDKs."""
    import types

    class AgentsFunctionTool:
        def __init__(self, *, name, description, params_json_schema, on_invoke_tool,
                     strict_json_schema=True):
            self.name, self.on_invoke_tool = name, on_invoke_tool

    class StructuredTool:
        def __init__(self, *, name, description, args_schema, func, coroutine=None):
            self.name, self.func = name, func

        def invoke(self, tool_input):
            return self.func(**tool_input)

    class ToolMetadata:
        def __init__(self, *, name, description, fn_schema):
            self.name = name

    class LlamaFunctionTool:
        def __init__(self, *, fn, metadata, async_fn=None):
            self.fn, self.metadata = fn, metadata

        def call(self, **kwargs):
            return self.fn(**kwargs)

    class CrewBaseTool:
        def __init__(self, *, name, description, args_schema):
            self.name = name

        def run(self, **kwargs):
            return self._run(**kwargs)

    class AutogenBaseTool:
        def __init__(self, args_type, return_type, name, description, strict=False):
            self.args_type, self.name = args_type, name

        async def run_json(self, args, cancellation_token):
            v = getattr(self.args_type, "model_validate", None)
            return await self.run(v(args) if v else args, cancellation_token)

    class CancellationToken:
        pass

    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        return m

    mods = {
        "agents": mod("agents", FunctionTool=AgentsFunctionTool),
        "langchain_core": mod("langchain_core"),
        "langchain_core.tools": mod("langchain_core.tools", StructuredTool=StructuredTool),
        "llama_index": mod("llama_index"),
        "llama_index.core": mod("llama_index.core"),
        "llama_index.core.tools": mod("llama_index.core.tools", FunctionTool=LlamaFunctionTool,
                                      ToolMetadata=ToolMetadata),
        "crewai": mod("crewai"),
        "crewai.tools": mod("crewai.tools", BaseTool=CrewBaseTool),
        "autogen_core": mod("autogen_core", CancellationToken=CancellationToken),
        "autogen_core.tools": mod("autogen_core.tools", BaseTool=AutogenBaseTool),
    }
    mods["langchain_core"].tools = mods["langchain_core.tools"]
    mods["llama_index"].core = mods["llama_index.core"]
    mods["llama_index.core"].tools = mods["llama_index.core.tools"]
    mods["crewai"].tools = mods["crewai.tools"]
    mods["autogen_core"].tools = mods["autogen_core.tools"]
    if importlib.util.find_spec("pydantic") is None:
        # Three adapters build an args model; on a base install stand in for
        # pydantic too (a class is all these examples need from it).
        mods["pydantic"] = mod("pydantic", Field=lambda default, description=None: default,
                               create_model=lambda name, **f: type(name, (), {}))
    return mods


def _adapter_examples() -> list[tuple[str, str, list[str]]]:
    """(heading, python source, expected output lines) per framework section."""
    out = []
    for heading in _ADAPTER_SECTIONS:
        body = _section(ADAPTERS_MD, heading)
        code = _fenced(body, "python")
        shown = _fenced(body, "text")
        assert len(code) == 1 and len(shown) == 1, heading
        out.append((heading, code[0], shown[0].splitlines()))
    return out


def test_adapters_doc_has_one_example_per_framework():
    headings = re.findall(r"^## (.+)$", ADAPTERS_MD, re.M)
    for h, module in _ADAPTER_SECTIONS.items():
        assert h in headings, h
        assert f"from {module} import arcaeon_tools" in _section(ADAPTERS_MD, h), h
    assert len(_adapter_examples()) == 5


def test_adapters_doc_examples_print_what_the_doc_says(tmp_path, monkeypatch, capsys):
    import io
    import threading
    from arcaeon.serve import server as S
    home = tmp_path / "home"
    root = tmp_path / "served"
    home.mkdir()
    root.mkdir()
    monkeypatch.setenv("ARCAEON_HOME", str(home))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.chdir(root)
    for name, m in _fake_frameworks().items():
        monkeypatch.setitem(sys.modules, name, m)
    for module in _ADAPTER_SECTIONS.values():
        monkeypatch.delitem(sys.modules, module, raising=False)
    token = "docs-adapters-token"
    (home / "serve.token").write_text(token, encoding="utf-8")
    server = S.make_server(port=0, token=token, root=root)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    try:
        assert ready.wait(10)
        for heading, code, expect in _adapter_examples():
            capsys.readouterr()
            exec(compile(code, f"docs/ADAPTERS.md#{heading}", "exec"), {"__name__": "__doc__"})
            got = capsys.readouterr().out.splitlines()
            assert got == expect, (heading, got, expect)
    finally:
        server.shutdown()
        t.join(10)
    assert not t.is_alive()


@pytest.mark.parametrize("phrase", ["tamper-proof", "independent", "truth", "is true",
                                    "compliant", "guarantee", "—", "–"])
def test_adapters_doc_makes_no_overclaim(phrase):
    assert phrase not in ADAPTERS_MD.lower(), phrase
