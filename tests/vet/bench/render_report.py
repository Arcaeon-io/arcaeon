"""Render the publishable markdown table from a summary JSON. Read-only: the
summary is the record, this file only lays it out.

    py projects/mcp_vet/bench/render_report.py bench/results/<stamp>_summary.json
    py projects/mcp_vet/bench/render_report.py ... --out bench/results/<stamp>_report.md

Refusals, on purpose: a summary without an `exclusions` block cannot be
rendered (every pass rate is printed next to what its denominator leaves
out, and there is nothing to print); a summary without the own-five block
cannot be rendered (ours go first, at their real gates, or the table does
not go out). TS and Python rows are never averaged: the language table
carries the checks that actually ran per language.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from summary_schema import (  # noqa: E402
    SummarySchemaError, validate_summary, wilson_interval,
    NO_HANDLER_REASONS, NO_HANDLER_UNCLASSIFIED)

# Copied verbatim from bench/PLAN.md, "What the number can and cannot say",
# first bullet; test_bench.py asserts PLAN.md still contains this string
# (whitespace-normalised, since the plan wraps at 80 columns).
BLIND_SPOT_PARAGRAPH = (
    "It is a static read of source. A server that logs through a platform the "
    "scanner cannot see (a logging config file, a sidecar, an HTTP gateway) "
    "scores lower than it deserves. The scanner says so in every grade's "
    "`blind_spots` and the report repeats it."
)

GATES = ("0", "1", "2", "3", "4")
GATE_NAMES = {"0": "no record", "1": "presence", "2": "completeness",
              "3": "tamper-evidence", "4": "reconstructable"}


class ReportError(ValueError):
    """The summary cannot be rendered into a publishable table."""


def _pct(k: int, n: int) -> str:
    return f"{k}/{n} ({100.0 * k / n:.1f}%)" if n else f"{k}/0 (n/a)"


def _exclusion_line(summ: dict) -> str:
    ex = summ["exclusions"]["excluded_from_headline"]
    return "Excludes: " + "; ".join(f"{e['what']} {e['n']}" for e in ex) + "."


def _ours_gate_word(d: dict) -> str:
    if d["outcome"] != "graded":
        return d["outcome"]
    return f"{d['gate']} ({GATE_NAMES.get(str(d['gate']), '?')})"


def render(summ: dict) -> str:
    if "exclusions" not in summ:
        raise ReportError("summary has no `exclusions` block; a pass rate without its "
                          "exclusion list is not publishable")
    if not summ.get("ours"):
        raise ReportError("summary has no own-five block (`ours`); our servers are reported "
                          "first, at their real gates, or the table does not go out")
    try:
        validate_summary(summ)
    except SummarySchemaError as e:
        raise ReportError(str(e)) from e

    stamp = summ["snapshot"].replace("registry_", "").replace(".jsonl", "")
    o = summ["outcomes"]
    graded_n = o.get("graded", 0)
    gd = summ["gate_distribution_graded"]
    k0 = gd.get("0", 0)
    lo, hi = wilson_interval(k0, graded_n) if graded_n else (0.0, 0.0)
    excl = _exclusion_line(summ)
    L: list[str] = []
    w = L.append

    w(f"# mcp-vet registry benchmark: snapshot {stamp}")
    w("")
    w("| snapshot sha256 | seed | mcp-vet | battery_digest |")
    w("|---|---|---|---|")
    w(f"| `{summ['snapshot_sha256']}` | `{summ['seed']}` | {summ['mcp_vet_version']} "
      f"| `{summ['battery_digest']}` |")
    w("")
    w(f"Plan fixed before grading: `{summ['plan']}`. Rendered read-only from "
      f"`bench/results/{stamp}_summary.json` by `bench/render_report.py`.")
    w("")

    # M26: ours first, outside the denominator, at the gates the run recorded.
    w("## Our own servers first (outside the sample)")
    w("")
    w("Graded with the same code, before the sample, at the version a stranger "
      "installs. Not in any denominator below; they do not improve the numbers.")
    w("")
    w("| server | outcome | audit-record gate | server file |")
    w("|---|---|---|---|")
    for d in summ["ours"]:
        best = [f for f, g in d["files"] if g == d["gate"]] if d["outcome"] == "graded" else []
        w(f"| {d['name'].replace('ours:', '')} | {d['outcome']} | {_ours_gate_word(d)} "
          f"| {', '.join(f'`{b}`' for b in best) or '(none)'} |")
    passing = [d for d in summ["ours"] if d["outcome"] == "graded" and d["gate"] == 4]
    w("")
    if not passing:
        w("None of our own servers reaches gate 4 in this run. The rows above are the "
          "PUBLISHED versions; they do not change until a fixed release is graded from "
          "the package index, not from a working tree.")
    else:
        w(f"{len(passing)} of {len(summ['ours'])} reach gate 4 in this run; the rest do not.")
    w("")

    # M25 + M31: headline with its interval and its exclusions.
    w("## Headline")
    w("")
    w(f"Of the {graded_n} graded sample repositories, **{_pct(k0, graded_n)}** leave no "
      f"record of a tool call on any tool-handling path (gate 0). 95% Wilson score "
      f"interval on that share: **{100 * lo:.1f}% to {100 * hi:.1f}%** (n = {graded_n}; "
      f"the interval is wide because the sample is small, and it says nothing about "
      f"the {o.get('no-handler-found', 0)} repositories the scanner could not read).")
    w("")
    w(f"Denominator = {graded_n} graded. {excl}")
    w("")

    w("## Gate ladder (graded sample repositories)")
    w("")
    w("| gate | meaning | n | share of graded |")
    w("|---|---|---|---|")
    for g in GATES:
        w(f"| {g} | {GATE_NAMES[g]} | {gd.get(g, 0)} | {_pct(gd.get(g, 0), graded_n)} |")
    w("")
    w(f"Denominator = {graded_n} graded. {excl}")
    w("")

    # M27: by language, checks_run column, never averaged.
    w("## By language (never averaged)")
    w("")
    w("Python files run the full battery; TypeScript/JavaScript files run ONE check. "
      "The rows below are separate populations and are not combined anywhere in "
      "this report. A repository with server files in both languages appears in "
      "both rows, so the rows do not sum to the graded count.")
    w("")
    w("| language | checks_run | n graded | " + " | ".join(f"gate {g}" for g in GATES) + " |")
    w("|---|---|---|" + "---|" * len(GATES))
    cr = summ.get("checks_run_by_lang", {})
    for lang, label in (("py", "Python"), ("ts", "TypeScript/JavaScript")):
        dist = summ["gate_by_lang"].get(lang, {})
        n = sum(dist.values())
        checks = cr.get(lang)
        checks_s = (f"{len(checks)}: " + ", ".join(checks)) if checks else "unrecorded"
        w(f"| {label} | {checks_s} | {n} | "
          + " | ".join(_pct(dist.get(g, 0), n) if n else "0/0" for g in GATES) + " |")
    w("")
    w(f"Denominators = per-language graded counts. {excl}")
    w("")

    # Outcomes of the sample, with the M20 split.
    n_sample = summ["sample_n"]
    w(f"## What happened to the {n_sample} sampled repositories")
    w("")
    w("| outcome | n | share of sample |")
    w("|---|---|---|")
    for key in ("graded", "no-handler-found", "clone-failed"):
        w(f"| {key} | {o.get(key, 0)} | {_pct(o.get(key, 0), n_sample)} |")
    w("")
    split = summ["no_handler_found_split"]
    w("no-handler-found, split by reason (sums to the count above):")
    w("")
    w("| reason | n |")
    w("|---|---|")
    for r in (*NO_HANDLER_REASONS, NO_HANDLER_UNCLASSIFIED):
        w(f"| {r} | {split.get(r, 0)} |")
    w("")
    if split.get(NO_HANDLER_UNCLASSIFIED, 0):
        w(summ.get("no_handler_found_split_note",
                   "unclassified rows predate the fields the classifier needs."))
        w("")
    w(f"Denominator = {n_sample} sampled. Excludes everything outside the sample "
      f"(see the population table).")
    w("")

    # M22: the whole population, every bucket.
    w("## Population (every server in exactly one bucket)")
    w("")
    w(f"{summ['servers_distinct_active']} distinct active servers in the snapshot; "
      f"sampling frame = `gradable:repo` ({summ['frame_gradable_repo']}).")
    w("")
    w("| bucket | n |")
    w("|---|---|")
    for b, n in summ["buckets"].items():
        w(f"| {b} | {n} |")
    w(f"| **total** | **{sum(summ['buckets'].values())}** |")
    w("")

    w("## Exclusions, in full")
    w("")
    w("| excluded from the headline | n | why |")
    w("|---|---|---|")
    for e in summ["exclusions"]["excluded_from_headline"]:
        w(f"| {e['what']} | {e['n']} | {e['why']} |")
    w("")

    # M32: the blind-spot paragraph, verbatim from the plan.
    w("## What this number cannot say")
    w("")
    w(BLIND_SPOT_PARAGRAPH)
    w("")
    w("It grades one check for TS/JS and says nothing about SSRF, exec, or secrets "
      "in those servers. `no-handler-found` is our blindness, not their fault. "
      "Reachability is capped at depth 2 from the handler; deeper records are "
      "reported as absent.")
    w("")
    w("## Reproduce")
    w("")
    w("`bench/REPRODUCE.md` lists the exact commands from the snapshot sha to this table.")
    w("")
    return "\n".join(L)


def main() -> int:
    import json
    ap = argparse.ArgumentParser()
    ap.add_argument("summary")
    ap.add_argument("--out")
    a = ap.parse_args()
    summ = json.loads(Path(a.summary).read_text(encoding="utf-8"))
    text = render(summ)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print("wrote", a.out)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
