#!/usr/bin/env python3
"""The GitHub Action's actual body, kept OUT of action.yml on purpose.

An action whose logic lives in a `run:` block of shell can only be tested by
pushing to GitHub and watching a run go red, which means it gets tested by
strangers on their own repos. Every decision the action makes -- which files to
grade, what the summary says, and above all which exit code it hands back --
lives here instead, driven entirely by environment variables, so the local
suite can run the identical code path against a planted fixture and a clean
file and assert red and green (`test_action.py`).

Inputs (composite actions hand `inputs.x` to the step as env; nothing here
reads the GitHub event, the actor, or a token, which is what makes it work
unchanged for a human's PR and for a bot-triggered push):

    INPUT_PATH        file or directory to grade          (default ".")
    INPUT_WARN_ONLY   "true" = report but never fail      (default "false")
    INPUT_OUTPUT      where to write the grade JSON       (default "mcp-vet-grade.json")
    INPUT_SUMMARY     "false" = skip the step summary     (default "true")
    MCP_VET_BIN       explicit path to the mcp-vet console script (escape hatch
                      for an install that is not on PATH)

GitHub-provided, both optional so this runs anywhere:

    GITHUB_STEP_SUMMARY   markdown appended here becomes the job summary
    GITHUB_OUTPUT         `name=value` lines become the step's outputs

Exit codes -- the contract the whole action is for:

    0  graded, nothing high-severity (or high-severity with warn-only on)
    1  at least one HIGH-severity finding, warn-only off. This is the red.
    2  configuration error: the path does not exist, holds no Python, or
       mcp-vet could not be run. Deliberately NOT 0 and NOT 1 -- a scan that
       never happened must not read as a clean bill of health, and must not
       read as findings either, because "we found nothing" and "we looked at
       nothing" are the two things a security gate must never confuse.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_CONFIG = 2

# Directories that are never a repo's own source. Grading a vendored copy of
# somebody else's package produces findings the caller cannot act on, and one
# unfixable red in CI is how a gate gets switched off for good.
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules",
    "__pycache__", "build", "dist", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".eggs", "site-packages",
}

DISCLAIMER = (
    "mcp-vet is not a vetting authority and certifies nothing. A clean grade means a "
    "small set of documented checks found nothing; every grade carries the list of "
    "what it did not look for."
)

# The job summary has a 1 MB ceiling and a reader has a much smaller one. Past
# this many rows the table stops being read and starts being scrolled.
MAX_SUMMARY_ROWS = 40

_SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def mcp_vet_cmd() -> list:
    """The argv prefix for mcp-vet.

    Order matters. `MCP_VET_BIN` wins because an operator who names a binary
    means that binary. Then the console script, because that is what
    `pip install mcp-vet` puts on PATH and what the action's install step
    produces -- running the real entry point means the action fails loudly if
    packaging breaks, instead of quietly succeeding through an import that only
    works from the source tree. `python -m mcp_vet` is the last resort, for a
    runner whose Scripts/ dir is not on PATH (a real and common Windows case).
    """
    explicit = os.environ.get("MCP_VET_BIN", "").strip()
    if explicit:
        return [explicit]
    found = shutil.which("mcp-vet")
    if found:
        return [found]
    return [sys.executable, "-m", "mcp_vet"]


def collect_targets(path: Path) -> list:
    if path.is_file():
        return [path]
    out = []
    for p in sorted(path.rglob("*.py")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        out.append(p)
    return out


def grade_one(cmd: list, target: Path) -> dict:
    """Shell out to `mcp-vet grade <file>` and parse the artifact.

    A subprocess rather than an import, on purpose: the grade a CI job publishes
    should be the output of the command a skeptic can run by hand on the same
    file. If those two can differ, the artifact is not re-testable, which is the
    only thing mcp-vet claims to sell.
    """
    try:
        proc = subprocess.run(cmd + ["grade", str(target)],
                              capture_output=True, text=True)
    except OSError as exc:
        # A half-finished install (the package resolved, the console script did
        # not land on PATH) must surface as the config error it is. Letting the
        # OSError propagate would exit 1 on Python's default, which is this
        # action's code for "high-severity findings" -- the tooling failure
        # would be read as a security result.
        raise RuntimeError(f"could not run mcp-vet as `{' '.join(cmd)}`: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"`{' '.join(cmd)} grade {target}` exited {proc.returncode}: "
            f"{(proc.stderr or proc.stdout).strip()[:800]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"mcp-vet did not emit JSON for {target}: {exc}; "
            f"first 200 bytes: {proc.stdout[:200]!r}") from exc


def worst_verdict(grades: list) -> str:
    """The envelope's verdict is the worst single file's, never an average.

    A repo with nine clean servers and one that hardcodes a live Stripe key is
    not 90% fine.
    """
    order = ["high-severity findings", "medium-severity findings",
             "low-severity findings", "informational findings only",
             "no findings in checked classes"]
    seen = {g.get("verdict") for g in grades}
    for v in order:
        if v in seen:
            return v
    return "no findings in checked classes"


def _rel(p: str) -> str:
    return str(p).replace("\\", "/")


def build_summary(envelope: dict, warn_only: bool) -> str:
    grades = envelope["grades"]
    findings = [(g, f) for g in grades for f in g["findings"]]
    findings.sort(key=lambda gf: (-_SEV_RANK.get(gf[1]["severity"], 0),
                                  _rel(gf[1]["file"]), gf[1]["line"]))
    high = envelope["high_severity_count"]

    icon = "❌" if (high and not warn_only) else ("⚠️" if high else "✅")
    lines = [
        "## mcp-vet grade",
        "",
        f"{icon} **{envelope['verdict']}** — `{_rel(envelope['path'])}`",
        "",
        f"mcp-vet {envelope['mcp_vet_version']} · "
        f"{envelope['files_graded']} file(s) graded · "
        f"{len(envelope['checks_run'])} checks run · "
        f"{envelope['findings_count']} finding(s) · "
        f"{envelope['blind_spots_count']} declared blind spots",
        "",
    ]
    if high and warn_only:
        lines += ["> `warn-only` is on, so this job stays green. "
                  f"{high} high-severity finding(s) would otherwise fail it.", ""]

    if findings:
        lines += ["| severity | check | location | detail |",
                  "|---|---|---|---|"]
        for _g, f in findings[:MAX_SUMMARY_ROWS]:
            detail = str(f["detail"]).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {f['severity']} | `{f['check']}` | "
                         f"`{_rel(f['file'])}:{f['line']}` | {detail} |")
        if len(findings) > MAX_SUMMARY_ROWS:
            lines.append(f"| … | | | {len(findings) - MAX_SUMMARY_ROWS} more "
                         f"finding(s) in the grade artifact |")
        lines.append("")
    else:
        lines += ["No findings in the checked classes.", ""]

    lines += [f"Checks run: {', '.join('`%s`' % c for c in envelope['checks_run'])}", ""]

    # The blind spots ride along in the summary, not just in the JSON nobody
    # opens. The confession IS the product; a summary that prints only the good
    # news is the closed-scanner behavior this tool exists to argue against.
    blind = envelope["blind_spots"]
    if blind:
        lines += [f"<details><summary>Declared blind spots ({len(blind)}) — what this "
                  f"grade did NOT check</summary>", ""]
        lines += [f"- {b}" for b in blind]
        lines += ["", "</details>", ""]

    lines += [f"_{DISCLAIMER}_",
              "",
              f"Full grade artifact: `{_rel(envelope['grade_path'])}` "
              f"(re-run any entry with `mcp-vet verify`).",
              ""]
    return "\n".join(lines)


def say(text: str, stream=None) -> None:
    """Print without ever being the reason the job failed.

    A GitHub runner on Windows hands Python a cp1252 stdout, and this summary
    carries a status glyph plus whatever characters the SCANNED repo's source
    put in a finding detail -- neither of which we control. Unguarded, that is a
    UnicodeEncodeError, which exits 1, which is this action's code for
    high-severity findings: the console encoding would have been reported as a
    security result. (Same failure the connector already has a test for; it
    found this one too, on the first real console run.)
    """
    stream = stream or sys.stdout
    try:
        print(text, file=stream)
    except UnicodeEncodeError:
        enc = getattr(stream, "encoding", None) or "ascii"
        print(text.encode(enc, "replace").decode(enc, "replace"), file=stream)


def _append(path_env: str, text: str) -> None:
    dest = os.environ.get(path_env)
    if not dest:
        return
    with open(dest, "a", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def main(argv=None) -> int:
    raw_path = (os.environ.get("INPUT_PATH") or ".").strip() or "."
    warn_only = env_flag("INPUT_WARN_ONLY", False)
    want_summary = env_flag("INPUT_SUMMARY", True)
    out_path = Path((os.environ.get("INPUT_OUTPUT") or "mcp-vet-grade.json").strip()
                    or "mcp-vet-grade.json")

    target = Path(raw_path)
    if not target.exists():
        say(f"::error::mcp-vet: path not found: {raw_path}", sys.stderr)
        return EXIT_CONFIG

    targets = collect_targets(target)
    if not targets:
        say(f"::error::mcp-vet: no Python files under {raw_path} - nothing was "
            f"graded, and an ungraded job is not a pass.", sys.stderr)
        return EXIT_CONFIG

    cmd = mcp_vet_cmd()
    grades = []
    for t in targets:
        try:
            grades.append(grade_one(cmd, t))
        except RuntimeError as exc:
            say(f"::error::{exc}", sys.stderr)
            return EXIT_CONFIG

    findings_count = sum(len(g["findings"]) for g in grades)
    high = sum(1 for g in grades for f in g["findings"] if f["severity"] == "high")
    # Read off the grades rather than restated here, the same rule grade.py
    # follows for `checks_run`: a summary that keeps its own copy of the check
    # list is a second source of truth that will drift from the first.
    checks_run = list(dict.fromkeys(c for g in grades for c in g["checks_run"]))
    blind_spots = list(dict.fromkeys(b for g in grades for b in g["blind_spots"]))

    envelope = {
        "schema": 1,
        "produced_by": "mcp-vet github action",
        "mcp_vet_version": grades[0].get("tool_version", "?"),
        "path": raw_path,
        "files_graded": len(grades),
        "verdict": worst_verdict(grades),
        "findings_count": findings_count,
        "high_severity_count": high,
        "checks_run": checks_run,
        "blind_spots": blind_spots,
        "blind_spots_count": len(blind_spots),
        "warn_only": warn_only,
        # Whole grades, unmodified. Each entry is a standalone artifact a
        # skeptic can save and re-run `mcp-vet verify` against; summarizing them
        # into counts here would throw away the only thing that makes the claim
        # checkable.
        "grades": grades,
    }
    envelope["grade_path"] = _rel(out_path)
    if out_path.parent and str(out_path.parent) not in ("", "."):
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")

    # Machine-readable first, human-readable last. Everything a downstream step
    # consumes is on disk before anything is written to a console we do not own.
    _append("GITHUB_OUTPUT",
            "\n".join([f"verdict={envelope['verdict']}",
                       f"grade-path={_rel(out_path)}",
                       f"files-graded={len(grades)}",
                       f"findings-count={findings_count}",
                       f"high-severity-count={high}",
                       f"blind-spots-count={len(blind_spots)}"]))

    summary = build_summary(envelope, warn_only)
    if want_summary:
        _append("GITHUB_STEP_SUMMARY", summary)
    say(summary)

    if high and not warn_only:
        say(f"::error::mcp-vet: {high} high-severity finding(s) - see the job "
            f"summary and {_rel(out_path)}", sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
