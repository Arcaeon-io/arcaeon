"""Versioned schema for a benchmark summary JSON (M23), the Wilson interval on
its headline share (M31), and the one-off backfill that brought the 2026-09-02
summary up to schema 1 by ADDING keys (never touching a number).

A summary that lacks any required key is not a summary: `render_report.py`
refuses it, and so does `grade_sample.py` before writing one. The point is
that a table can never be published without the sha it was computed from,
the seed that picked the sample, the version and battery that graded it,
and the list of what the headline denominator leaves out.

    py projects/mcp_vet/bench/summary_schema.py --validate bench/results/<stamp>_summary.json
    py projects/mcp_vet/bench/summary_schema.py --backfill bench/results/<stamp>_summary.json
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

SCHEMA_VERSION = 1

# Every key a schema-1 summary must carry. Comments say why each is there.
REQUIRED_KEYS = (
    "schema",                     # this integer; a reader rejects an unknown one
    "snapshot",                   # snapshot file name
    "snapshot_sha256",            # the population, content-addressed
    "seed",                       # seed EXPRESSION (how the sample was picked)
    "mcp_vet_version",            # tool version that graded
    "plan",                       # path of the sampling plan fixed before grading
    "servers_distinct_active",    # the denominator of the population
    "buckets",                    # every server in exactly one bucket (M22)
    "frame_gradable_repo",        # the sampling frame
    "sample_n",
    "outcomes",                   # graded / no-handler-found / clone-failed
    "gate_distribution_graded",   # the gate histogram
    "gate_by_lang",               # never averaged across languages (M27)
    "ours",                       # the own-five block, reported first (M26)
    "exclusions",                 # what every pass rate sits next to (M25)
    "battery_digest",             # sha256 of the check battery (or "unrecorded:...")
    "no_handler_found_split",     # M20 sub-reasons; must sum to outcomes[no-handler-found]
)

NO_HANDLER_REASONS = ("unsupported-language", "monorepo-miss", "no-handler")
NO_HANDLER_UNCLASSIFIED = "unclassified:pre-M20-row"


class SummarySchemaError(ValueError):
    """The summary is missing something a published table must carry."""


def validate_summary(summ: dict) -> dict:
    missing = [k for k in REQUIRED_KEYS if k not in summ]
    if missing:
        raise SummarySchemaError(f"summary missing required keys: {missing}")
    if summ["schema"] != SCHEMA_VERSION:
        raise SummarySchemaError(
            f"summary schema {summ['schema']!r} is not {SCHEMA_VERSION}")
    if not isinstance(summ["exclusions"], dict) or not summ["exclusions"].get("excluded_from_headline"):
        raise SummarySchemaError("exclusions block is empty; a pass rate needs its exclusion list")
    if not summ["ours"]:
        raise SummarySchemaError("own-five block is empty; ours are reported first or not at all")
    split = summ["no_handler_found_split"]
    want = summ["outcomes"].get("no-handler-found", 0)
    if sum(split.values()) != want:
        raise SummarySchemaError(
            f"no_handler_found_split sums to {sum(split.values())}, outcomes say {want}")
    if sum(summ["buckets"].values()) != summ["servers_distinct_active"]:
        raise SummarySchemaError("buckets do not sum to servers_distinct_active")
    return summ


def wilson_interval(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for a binomial share k/n at 95% (z = 1.96).
    Chosen over the normal approximation because the headline share is near
    the edge (30/33) where the normal interval runs past 100%."""
    if n <= 0:
        raise ValueError("n must be positive")
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def exclusions_block(summ: dict) -> dict:
    """Everything the headline denominator (the graded count) leaves out, with
    its count, computed from the summary's own numbers so it cannot disagree
    with them."""
    b = summ["buckets"]
    o = summ["outcomes"]
    graded = o.get("graded", 0)
    frame = summ["frame_gradable_repo"]
    return {
        "headline_denominator": {
            "n": graded,
            "what": "sample repos where a handler file was found and the audit-record check applied",
        },
        "excluded_from_headline": [
            {"what": "ours", "n": len(summ["ours"]),
             "why": "our own servers, graded with the same code, reported first and outside the sample"},
            {"what": "no-handler-found", "n": o.get("no-handler-found", 0),
             "why": "cloned, but no file with a handler marker the scanner knows; our blindness, not their fault"},
            {"what": "clone-failed", "n": o.get("clone-failed", 0),
             "why": "private or deleted repository; nothing to read"},
            {"what": "frame-not-sampled", "n": frame - summ["sample_n"],
             "why": "gradable:repo servers outside the seeded sample of " + str(summ["sample_n"])},
            {"what": "gradable:package-only", "n": b.get("gradable:package-only", 0),
             "why": "a package but no repository URL; not graded in v1"},
            {"what": "ungradable:remote-only", "n": b.get("ungradable:remote-only", 0),
             "why": "a URL and nothing else; a source scanner cannot see it"},
            {"what": "ungradable:no-source-no-remote", "n": b.get("ungradable:no-source-no-remote", 0),
             "why": "registry row with neither source nor remote"},
        ],
    }


def checks_run_by_lang(sample_rows: list[dict]) -> dict:
    """Which checks actually ran per language, read off the rows themselves so
    the report column is a record, not a claim."""
    seen: dict[str, set] = {}
    for row in sample_rows:
        for f in row.get("files", []):
            seen.setdefault(f["lang"], set()).add(tuple(f["checks_run"]))
    out = {}
    for lang, variants in sorted(seen.items()):
        if len(variants) != 1:
            raise SummarySchemaError(f"{lang}: rows disagree on checks_run: {variants}")
        out[lang] = list(next(iter(variants)))
    return out


def backfill(summ: dict, sample_rows: list[dict], battery_now: str, stamp: str) -> dict:
    """Bring a pre-schema summary up to schema 1 by adding keys ONLY. Every key
    that was already there keeps its value (asserted). The battery digest of a
    run that predates the field is not recoverable and is recorded as such;
    the digest of the tree at backfill time is kept beside it, labelled."""
    before = json.dumps(summ, sort_keys=True)
    out = dict(summ)
    add = {}
    add["schema"] = SCHEMA_VERSION
    add["exclusions"] = exclusions_block(summ)
    add["battery_digest"] = "unrecorded:run-predates-schema-1"
    add["battery_digest_at_backfill"] = battery_now
    add["checks_run_by_lang"] = checks_run_by_lang(sample_rows)
    n_nh = summ["outcomes"].get("no-handler-found", 0)
    add["no_handler_found_split"] = {**{r: 0 for r in NO_HANDLER_REASONS},
                                     NO_HANDLER_UNCLASSIFIED: n_nh}
    add["no_handler_found_split_note"] = (
        "rows graded before M20 carry no repo_markers/manifest_dirs/scanned_dirs, "
        "so the historical no-handler-found rows cannot be split; they are "
        "counted as unclassified and the three reasons are 0 until a re-run.")
    add["backfill_note"] = (
        f"schema 1 keys added {stamp} by bench/summary_schema.py --backfill; "
        "no pre-existing key changed. battery_digest is unrecorded because the "
        "run predates the field; battery_digest_at_backfill is the working tree "
        "at backfill time, which is NOT the tree that graded.")
    for k, v in add.items():
        if k in out:
            if out[k] != v:
                raise SummarySchemaError(f"backfill would change existing key {k!r}; refusing")
            continue
        out[k] = v
    for k in summ:
        if json.dumps(out[k], sort_keys=True) != json.dumps(summ[k], sort_keys=True):
            raise SummarySchemaError(f"backfill changed {k!r}; refusing")
    assert json.dumps({k: out[k] for k in summ}, sort_keys=True) == before
    return validate_summary(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate")
    ap.add_argument("--backfill")
    a = ap.parse_args()
    if a.validate:
        validate_summary(json.loads(Path(a.validate).read_text(encoding="utf-8")))
        print("ok: schema", SCHEMA_VERSION)
        return 0
    if a.backfill:
        from datetime import datetime, timezone
        from arcaeon.prove.vet.badge import battery_digest
        path = Path(a.backfill)
        text = path.read_text(encoding="utf-8")
        summ = json.loads(text)
        rows_path = path.with_name(path.name.replace("_summary.json", "_sample.jsonl"))
        rows = [json.loads(l) for l in rows_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%MZ")
        out = backfill(summ, rows, battery_digest(), stamp)
        new_text = json.dumps(out, indent=2)
        # The old file must survive as a byte prefix (minus its closing brace).
        assert new_text.startswith(text.rstrip().rstrip("}").rstrip()), "prefix changed"
        path.write_text(new_text, encoding="utf-8")
        print("backfilled:", path, "added", [k for k in out if k not in summ])
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
