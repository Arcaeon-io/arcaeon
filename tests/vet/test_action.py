"""The GitHub Action, tested without GitHub.

A CI gate is the one piece of this project that fails in somebody else's repo,
on a runner nobody here can see, usually at the moment they most needed it to
work. So the action's body is a plain script driven by environment variables
(`action/run_vet.py`) and this file runs it exactly the way the runner does:
env in, files out, exit code asserted.

The two assertions that matter are the red and the green. Red: the planted
credential fixture must exit nonzero, because a security gate that cannot fail
is decoration. Green: a clean file must exit zero, because a gate that always
fails gets deleted in a week. Everything else here guards a way the two could
quietly stop meaning what they say -- a scan that never ran reporting as a pass,
the summary losing the blind-spot confession, or action.yml drifting away from
the script it calls.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent
ACTION_DIR = ROOT / "action"
ACTION_YML = ACTION_DIR / "action.yml"
PLANTED = ROOT / "tests" / "fixtures" / "secret_in_code_server.py"

# A server that registers a handler and never serves: no sink, and MCP08 is not
# asked of a file with no entrypoint, so this is genuinely clean rather than
# clean-because-empty.
CLEAN_SOURCE = '''"""A tool that adds two numbers and touches nothing."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean")


@mcp.tool()
def add(a, b):
    return a + b
'''


def _load_run_vet():
    spec = importlib.util.spec_from_file_location("mcp_vet_action_run_vet",
                                                  ACTION_DIR / "run_vet.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


run_vet = _load_run_vet()
SRC = Path(__file__).resolve().parents[2] / "src"   # arcaeon merge: the moved package


@pytest.fixture
def act(monkeypatch, tmp_path):
    """Run the action's core exactly as the runner does, and hand back
    (exit_code, envelope, summary_text, outputs_dict)."""
    # run_vet shells out to `mcp-vet grade`. On a runner that is the installed
    # console script; here nothing is on PATH, so it falls through to
    # `python -m mcp_vet` -- and PYTHONPATH is what makes that resolve no matter
    # which directory pytest was started from.
    prior = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv("PYTHONPATH", str(ROOT) + (os.pathsep + prior if prior else ""))
    monkeypatch.delenv("MCP_VET_BIN", raising=False)
    # arcaeon merge: run_vet.py stays byte-identical to the Marketplace copy (it
    # shells to `mcp-vet`, or `python -m mcp_vet`). This machine still has the OLD
    # mcp-vet installed, so point MCP_VET_BIN at a one-line wrapper around the
    # MOVED code; otherwise these tests would quietly grade with the old package.
    wrapper = tmp_path / ("mcp-vet.cmd" if os.name == "nt" else "mcp-vet")
    if os.name == "nt":
        wrapper.write_text(f'@set "PYTHONPATH={SRC};%PYTHONPATH%"' + chr(10)
                           + f'@"{sys.executable}" -m arcaeon.prove.vet %*' + chr(10),
                           encoding="utf-8")
    else:
        wrapper.write_text("#!/bin/sh" + chr(10)
                           + f'PYTHONPATH="{SRC}:$PYTHONPATH" exec "{sys.executable}" '
                           + '-m arcaeon.prove.vet "$@"' + chr(10), encoding="utf-8")
        wrapper.chmod(0o755)
    monkeypatch.setenv("MCP_VET_BIN", str(wrapper))

    def _run(path, **inputs):
        summary_file = tmp_path / "step_summary.md"
        output_file = tmp_path / "step_output.txt"
        grade_file = inputs.pop("output", tmp_path / "grade.json")
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
        monkeypatch.setenv("INPUT_PATH", str(path))
        monkeypatch.setenv("INPUT_OUTPUT", str(grade_file))
        for k, v in inputs.items():
            monkeypatch.setenv("INPUT_" + k.upper().replace("-", "_"), str(v))

        code = run_vet.main()

        envelope = None
        if Path(grade_file).is_file():
            envelope = json.loads(Path(grade_file).read_text(encoding="utf-8"))
        summary = summary_file.read_text(encoding="utf-8") if summary_file.is_file() else ""
        outputs = {}
        if output_file.is_file():
            for line in output_file.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    outputs[k] = v
        return code, envelope, summary, outputs

    return _run


# --- red -------------------------------------------------------------------

def test_the_planted_fixture_fails_the_job(act):
    """The whole point of the action, in one assertion. tests/fixtures/
    secret_in_code_server.py carries three hard-coded vendor credentials; if
    this ever exits 0 the gate is open and every downstream repo using it
    believes it is protected."""
    assert PLANTED.is_file(), "the planted fixture is gone; this test proves nothing"
    code, env, summary, outputs = act(PLANTED)

    assert code == run_vet.EXIT_FINDINGS, (code, summary)
    assert env["verdict"] == "high-severity findings"
    assert env["high_severity_count"] == 3, env["high_severity_count"]
    assert outputs["high-severity-count"] == "3"
    assert all(f["check"] == "secret-in-code" for g in env["grades"] for f in g["findings"])


def test_warn_only_reports_the_same_red_without_failing(act):
    """The migration path onto an existing repo. It must still SAY high, in the
    summary and in the artifact -- a warn-only that also softens the wording is
    how a team stops seeing the finding at all."""
    code, env, summary, outputs = act(PLANTED, warn_only="true")

    assert code == run_vet.EXIT_OK
    assert env["verdict"] == "high-severity findings"
    assert env["high_severity_count"] == 3
    assert env["warn_only"] is True
    assert "warn-only" in summary and "high-severity finding(s) would otherwise fail" in summary


def test_the_severity_that_fails_is_high_and_only_high(act, tmp_path):
    """A medium finding must not fail the job. mcp-vet's medium bucket is
    heuristic by construction (entropy, gate ladders), and a gate that reds on a
    heuristic gets turned off by the first false positive."""
    src = tmp_path / "medium_only.py"
    src.write_text('SERVICE_TOKEN = "a7Kd93Lm2Qx8Zb4Vn6Wp1Rt5Yu0Hc"\n', encoding="utf-8")
    code, env, summary, _ = act(src)

    sevs = {f["severity"] for g in env["grades"] for f in g["findings"]}
    assert sevs == {"medium"}, sevs
    assert env["verdict"] == "medium-severity findings"
    assert code == run_vet.EXIT_OK, "a medium finding must not fail the build"


# --- green -----------------------------------------------------------------

def test_a_clean_file_passes(act, tmp_path):
    src = tmp_path / "clean_server.py"
    src.write_text(CLEAN_SOURCE, encoding="utf-8")
    code, env, summary, outputs = act(src)

    assert code == run_vet.EXIT_OK, summary
    assert env["verdict"] == "no findings in checked classes"
    assert env["findings_count"] == 0
    assert outputs["findings-count"] == "0"
    assert "No findings in the checked classes." in summary


# --- the scan that did not happen -------------------------------------------

def test_a_missing_path_is_a_config_error_not_a_pass(act, tmp_path):
    code, env, summary, _ = act(tmp_path / "nope" / "there.py")
    assert code == run_vet.EXIT_CONFIG
    assert env is None, "no artifact should be written for a scan that never ran"


def test_a_directory_with_no_python_is_a_config_error_not_a_pass(act, tmp_path):
    (tmp_path / "empty").mkdir()
    (tmp_path / "empty" / "README.md").write_text("nothing here", encoding="utf-8")
    code, _env, _summary, _ = act(tmp_path / "empty")
    assert code == run_vet.EXIT_CONFIG, (
        "an empty scan reported as green is the failure mode this exit code exists for")


def test_a_broken_mcp_vet_is_a_config_error_not_a_pass(act, monkeypatch, tmp_path):
    """If the install step half-worked, the job must go red on the tooling, not
    green on an empty result."""
    src = tmp_path / "clean_server.py"
    src.write_text(CLEAN_SOURCE, encoding="utf-8")
    monkeypatch.setenv("MCP_VET_BIN", str(tmp_path / "not_a_real_binary"))
    code, env, _summary, _ = act(src)
    # Not 1: Python's default exit on an uncaught exception is 1, which is this
    # action's code for high-severity findings. A tooling failure read as a
    # security result is worse than either.
    assert code == run_vet.EXIT_CONFIG, code
    assert env is None


# --- directories ------------------------------------------------------------

def test_a_directory_grades_every_python_file_and_takes_the_worst_verdict(act, tmp_path):
    tree = tmp_path / "repo"
    (tree / "pkg").mkdir(parents=True)
    (tree / "pkg" / "clean.py").write_text(CLEAN_SOURCE, encoding="utf-8")
    (tree / "pkg" / "leaky.py").write_text(PLANTED.read_text(encoding="utf-8"),
                                           encoding="utf-8")
    code, env, _summary, outputs = act(tree)

    assert env["files_graded"] == 2, [g["target"] for g in env["grades"]]
    assert outputs["files-graded"] == "2"
    assert env["verdict"] == "high-severity findings", (
        "one clean file out of two must not average away the credential")
    assert code == run_vet.EXIT_FINDINGS


def test_vendored_and_build_directories_are_skipped(act, tmp_path):
    """A red the caller cannot fix (somebody else's code in .venv/) is how a
    gate gets switched off permanently."""
    tree = tmp_path / "repo"
    for junk in (".venv/lib/site-packages", "node_modules/x", "build/lib", "__pycache__"):
        d = tree / junk
        d.mkdir(parents=True)
        (d / "leaky.py").write_text(PLANTED.read_text(encoding="utf-8"), encoding="utf-8")
    (tree / "ours.py").write_text(CLEAN_SOURCE, encoding="utf-8")

    code, env, _summary, _ = act(tree)
    assert env["files_graded"] == 1, [g["target"] for g in env["grades"]]
    assert code == run_vet.EXIT_OK


# --- the artifact -----------------------------------------------------------

def test_every_grade_in_the_artifact_still_verifies_against_its_source(act, tmp_path):
    """The artifact is only worth publishing if a skeptic can re-run it. Each
    entry goes through mcp_vet.grade.verify -- the same call `mcp-vet verify`
    makes -- against the bytes it claims to have graded."""
    from arcaeon.prove.vet.grade import verify

    src = tmp_path / "leaky.py"
    src.write_text(PLANTED.read_text(encoding="utf-8"), encoding="utf-8")
    _code, env, _summary, _ = act(src)

    for grade in env["grades"]:
        result = verify(grade, Path(grade["target"]).read_bytes().decode("utf-8"))
        assert result["reproduced"], (grade["target"], result["reasons"])


def test_the_artifact_reads_its_checks_and_blind_spots_off_the_grades(act):
    """Same rule grade.py lives under: the summary must not keep its own copy of
    the check list. Asserted by comparing against the per-file grade, so a
    hand-maintained list in the action would show up here as drift."""
    _code, env, _summary, _ = act(PLANTED)
    only = env["grades"][0]
    assert env["checks_run"] == only["checks_run"]
    assert env["blind_spots"] == only["blind_spots"]
    assert env["blind_spots_count"] == len(only["blind_spots"]) > 0


# --- the summary ------------------------------------------------------------

def test_the_summary_carries_verdict_checks_run_and_the_blind_spot_count(act):
    _code, env, summary, _ = act(PLANTED)
    assert "## mcp-vet grade" in summary
    assert "high-severity findings" in summary
    for check in env["checks_run"]:
        assert f"`{check}`" in summary, f"{check} missing from the summary"
    assert f"{env['blind_spots_count']} declared blind spots" in summary
    assert f"{len(env['checks_run'])} checks run" in summary


def test_the_summary_confesses_the_blind_spots_not_just_the_findings(act):
    """The confession is the product. A CI summary that prints only what was
    found teaches the reader that a green means safe, which is the exact claim
    this project refuses to make."""
    _code, env, summary, _ = act(PLANTED)
    assert "Declared blind spots" in summary
    for spot in env["blind_spots"]:
        assert spot in summary, spot[:60]
    assert "not a vetting authority" in summary


def test_the_summary_is_appended_not_overwritten(act, tmp_path, monkeypatch):
    """$GITHUB_STEP_SUMMARY is shared with every other step in the job."""
    summary_file = tmp_path / "shared_summary.md"
    summary_file.write_text("## an earlier step said something\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    monkeypatch.setenv("INPUT_PATH", str(PLANTED))
    monkeypatch.setenv("INPUT_OUTPUT", str(tmp_path / "g.json"))
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    run_vet.main()
    text = summary_file.read_text(encoding="utf-8")
    assert text.startswith("## an earlier step said something")
    assert "## mcp-vet grade" in text


def test_it_runs_with_no_github_environment_at_all(act, monkeypatch, tmp_path):
    """Nothing here may require the runner. Same script, no GITHUB_* vars: it
    still grades, still writes the artifact, still returns the right code."""
    src = tmp_path / "leaky.py"
    src.write_text(PLANTED.read_text(encoding="utf-8"), encoding="utf-8")
    grade_file = tmp_path / "g.json"
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    monkeypatch.setenv("INPUT_PATH", str(src))
    monkeypatch.setenv("INPUT_OUTPUT", str(grade_file))
    monkeypatch.delenv("INPUT_WARN_ONLY", raising=False)
    monkeypatch.delenv("INPUT_SUMMARY", raising=False)

    assert run_vet.main() == run_vet.EXIT_FINDINGS
    assert json.loads(grade_file.read_text(encoding="utf-8"))["high_severity_count"] == 3


def test_the_summary_survives_a_cp1252_console(act, monkeypatch):
    """Found by running the script for real, not by reading it: a GitHub runner
    on Windows hands Python a cp1252 stdout, the summary's status glyph is not
    in cp1252, and the UnicodeEncodeError exited 1 — this action's code for
    high-severity findings. A console encoding reported as a security result,
    with the step outputs never written because the crash came first."""
    import io

    buf = io.BytesIO()
    monkeypatch.setattr(sys, "stdout",
                        io.TextIOWrapper(buf, encoding="cp1252", errors="strict"))
    code, env, _summary, outputs = act(PLANTED)
    sys.stdout.flush()

    assert code == run_vet.EXIT_FINDINGS
    assert env["high_severity_count"] == 3
    assert outputs["high-severity-count"] == "3", (
        "the step outputs must be written before anything touches the console")
    assert b"mcp-vet grade" in buf.getvalue()


def test_the_step_outputs_are_written_before_the_console_is_touched():
    """The ordering the test above depends on, asserted directly so a later
    tidy-up cannot swap the two lines back."""
    body = (ACTION_DIR / "run_vet.py").read_text(encoding="utf-8")
    assert body.index('_append("GITHUB_OUTPUT"') < body.index("say(summary)")


# --- action.yml itself ------------------------------------------------------

def _action():
    return yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))


def test_the_action_is_composite_and_calls_the_script_these_tests_exercise():
    a = _action()
    assert a["runs"]["using"] == "composite"
    run_steps = [s for s in a["runs"]["steps"] if "run" in s]
    assert any("run_vet.py" in s["run"] for s in run_steps), (
        "action.yml no longer calls run_vet.py, so this whole file tests nothing")
    assert all("shell" in s for s in run_steps), "a composite run step needs an explicit shell"


def test_the_action_never_checks_out_and_never_needs_a_human():
    """Bot-triggered pushes and human PRs must take the identical path."""
    text = ACTION_YML.read_text(encoding="utf-8")
    a = _action()
    uses = [s.get("uses", "") for s in a["runs"]["steps"]]
    assert not any("actions/checkout" in u for u in uses), (
        "the caller checks out; an action that does it for you gets the ref wrong")
    for forbidden in ("read -p", "gh auth login", "input(", "GITHUB_TOKEN", "secrets."):
        assert forbidden not in text, f"{forbidden!r} makes this need a human or a secret"


def test_no_input_is_interpolated_into_a_shell_body():
    """`${{ inputs.x }}` pasted into a run: block is a command injection, in an
    action whose subject is supply-chain hygiene. Inputs go through env."""
    for step in _action()["runs"]["steps"]:
        body = step.get("run", "")
        assert "${{" not in body, (step.get("name"), body)


def test_the_script_inputs_are_all_wired_through_the_grade_step():
    """action.yml declares the inputs; run_vet.py reads env vars. Nothing
    connects them but this step's env block, so it gets a test."""
    grade_step = next(s for s in _action()["runs"]["steps"] if s.get("id") == "grade")
    wired = set(grade_step["env"])
    assert {"INPUT_PATH", "INPUT_WARN_ONLY", "INPUT_OUTPUT", "INPUT_SUMMARY"} <= wired, wired


def test_declared_outputs_match_what_the_script_actually_writes(act):
    """The other half of the same seam: an output declared in action.yml that
    the script never writes is an empty string handed to whatever consumes it."""
    _code, _env, _summary, outputs = act(PLANTED)
    declared = set(_action()["outputs"])
    assert declared == set(outputs), (declared ^ set(outputs))
    for name, spec in _action()["outputs"].items():
        assert f"steps.grade.outputs.{name}" in spec["value"], (name, spec)


def test_the_action_declares_the_python_floor_the_package_requires():
    """mcp-vet is >= 3.10. A default of 3.9 here would install and then fail on
    a syntax error in somebody else's CI."""
    default = str(_action()["inputs"]["python-version"]["default"])
    major, minor = (int(x) for x in default.split(".")[:2])
    assert (major, minor) >= (3, 10), default


# --- the standalone Marketplace repo -----------------------------------------
# GitHub Marketplace only drafts a release off an action.yml at a repo ROOT
# so the listable copy lives in a separate, standalone repo,
# not this monorepo. That copy must never drift from this one silently --
# copy both files across verbatim before each tag. This SKIPS rather than fails when the
# standalone checkout is not present on the machine running the suite (it is
# a separate checkout named by ARCAEON_VET_ACTION_REPO);
# on the one machine that has both, a missed sync step turns into a real
# failure instead of a quiet divergence nobody notices until Marketplace
# publish time.
import os as _os
_STANDALONE_ENV = _os.environ.get("ARCAEON_VET_ACTION_REPO")
STANDALONE_REPO = Path(_STANDALONE_ENV) if _STANDALONE_ENV else None


@pytest.mark.skipif(STANDALONE_REPO is None or not STANDALONE_REPO.exists(),
                     reason="ARCAEON_VET_ACTION_REPO is not set to the standalone "
                            "action checkout")
def test_action_matches_standalone_copy():
    """action.yml here and in the standalone repo must be byte-identical.

    Anything else means the copy step was skipped, done partially, or
    the standalone copy was hand-edited directly (which the next sync would
    silently clobber anyway -- this catches the drift before that happens)."""
    ours = ACTION_YML.read_bytes()
    theirs = (STANDALONE_REPO / "action.yml").read_bytes()
    assert ours == theirs, (
        "action.yml has drifted from the standalone Marketplace repo copy -- "
        "copy the file across verbatim before tagging a release")


@pytest.mark.skipif(STANDALONE_REPO is None or not STANDALONE_REPO.exists(),
                     reason="ARCAEON_VET_ACTION_REPO is not set to the standalone "
                            "action checkout")
def test_run_vet_matches_standalone_copy():
    """Same drift check as above, for the script action.yml actually calls."""
    ours = (ACTION_DIR / "run_vet.py").read_bytes()
    theirs = (STANDALONE_REPO / "run_vet.py").read_bytes()
    assert ours == theirs, (
        "run_vet.py has drifted from the standalone Marketplace repo copy -- "
        "copy the file across verbatim before tagging a release")
