"""Tests for the registry benchmark's bookkeeping (bench/, 2026-09-02 batch,
items M19 M20 M22 M23 M24-M28 M29 M30 M31 M32).

None of these touch the registry, clone anything, or read the 36 MB snapshot.
Every population is a synthetic snapshot built in the test.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parent / "bench"
sys.path.insert(0, str(BENCH))

import grade_sample as gs  # noqa: E402
import render_report as rr  # noqa: E402
import summary_schema as ss  # noqa: E402

PLAN = BENCH / "PLAN.md"
REAL_SUMMARY = BENCH / "results" / "2026-09-02T2142Z_summary.json"


# --- synthetic snapshot -------------------------------------------------------

def _row(name, *, version="1.0.0", latest=True, status="active", repo=None,
         pkgs=(), remotes=()):
    r = {"name": name, "title": name, "version": version, "is_latest": latest,
         "status": status, "published_at": "2026-09-01T00:00:00Z",
         "repo_url": repo, "repo_source": "github" if repo else None,
         "repo_subfolder": None,
         "package_registries": sorted(pkgs), "package_ids": [],
         "remote_types": sorted(remotes)}
    r["gradability"] = gs.gradability(r)
    return r


def synthetic_snapshot():
    rows = [
        _row("a/one", repo="https://github.com/a/one", pkgs=["npm"]),
        _row("a/one", version="0.9.0", latest=False, repo="https://github.com/a/one"),  # version row
        _row("a/two", repo="https://github.com/a/two"),
        _row("a/three", pkgs=["pypi"]),                     # package-only
        _row("a/four", remotes=["streamable-http"]),        # remote-only
        _row("a/five"),                                     # nothing
        _row("a/six", status="deprecated", repo="https://github.com/a/six"),
        _row("a/seven", repo="https://github.com/a/seven"),
        _row("a/eight", repo="https://github.com/a/eight"),
        _row("a/nine", repo="https://github.com/a/nine"),
    ]
    return rows


SHA = "4990529da87c02f3f783b84bbead3ab15d43ddb642d1311989776c34a648dbe2"


# --- M22: denominator ---------------------------------------------------------

def test_every_row_lands_in_exactly_one_bucket_and_buckets_sum_to_active():
    pop = gs.population(synthetic_snapshot())
    assert len(pop) == 8                      # 10 rows minus 1 version row minus 1 deprecated
    counts = gs.bucket_counts(pop)
    assert set(counts) == set(gs.BUCKETS)
    assert sum(counts.values()) == len(pop)
    assert counts == {"gradable:repo": 5, "gradable:package-only": 1,
                      "ungradable:remote-only": 1, "ungradable:no-source-no-remote": 1}


def test_planted_unbucketed_row_fails_the_denominator():
    pop = gs.population(synthetic_snapshot())
    pop[2]["gradability"] = "gradable:mystery"
    with pytest.raises(gs.BucketError, match="mystery"):
        gs.bucket_counts(pop)


def test_planted_mislabelled_row_fails_the_denominator():
    """A label that disagrees with the row's own fields is also a bug: the
    scrape stamped it, the benchmark recomputes it."""
    pop = gs.population(synthetic_snapshot())
    remote = next(r for r in pop if r["gradability"] == "ungradable:remote-only")
    remote["gradability"] = "gradable:repo"   # claims a repo it does not have
    with pytest.raises(gs.BucketError, match="fields say"):
        gs.bucket_counts(pop)


# --- M29: seed determinism ---------------------------------------------------

def test_same_snapshot_same_sample_order_twice():
    pop = gs.population(synthetic_snapshot())
    first, frame_n = gs.sample(pop, SHA, 3)
    second, _ = gs.sample(pop, SHA, 3)
    assert frame_n == 5
    assert [r["name"] for r in first] == [r["name"] for r in second]
    other, _ = gs.sample(pop, "ffffffff" + SHA[8:], 3)
    assert [r["name"] for r in other] != [r["name"] for r in first] or len(first) < 2


# --- M30: append-only results -----------------------------------------------

def test_results_append_only_identical_noop_differing_raises(tmp_path):
    path = tmp_path / "x_sample.jsonl"
    row = {"name": "a/one", "outcome": "graded", "gate": 0, "files": [], "langs": {}, "seconds": 1.2}
    done = gs.load_results(path)
    with path.open("a", encoding="utf-8") as fh:
        gs.append_row(fh, done, row)
    before = path.read_text(encoding="utf-8")

    done = gs.load_results(path)
    with path.open("a", encoding="utf-8") as fh:
        same = gs.append_row(fh, done, {**row, "seconds": 9.9})   # only wall-clock differs
    assert same["seconds"] == 1.2
    assert path.read_text(encoding="utf-8") == before               # no-op

    with path.open("a", encoding="utf-8") as fh:
        with pytest.raises(gs.ResultConflict, match="a/one"):
            gs.append_row(fh, done, {**row, "gate": 4})             # planted conflict
    assert path.read_text(encoding="utf-8") == before


def test_results_file_with_conflicting_duplicate_refuses_to_load(tmp_path):
    path = tmp_path / "x_sample.jsonl"
    a = {"name": "a/one", "outcome": "graded", "gate": 0}
    path.write_text(json.dumps(a) + "\n" + json.dumps({**a, "gate": 2}) + "\n", encoding="utf-8")
    with pytest.raises(gs.ResultConflict):
        gs.load_results(path)


# --- M19 + M20: monorepo layout and the no-handler classifier ---------------

PY_SERVER = '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b

if __name__ == "__main__":
    mcp.run()
'''


def _monorepo(tmp_path: Path) -> Path:
    dest = tmp_path / "repo"
    (dest / "docs").mkdir(parents=True)
    (dest / "docs" / "README.md").write_text("docs only\n", encoding="utf-8")
    (dest / "packages" / "server").mkdir(parents=True)
    (dest / "packages" / "server" / "pyproject.toml").write_text("[project]\nname='s'\n", encoding="utf-8")
    (dest / "packages" / "server" / "server.py").write_text(PY_SERVER, encoding="utf-8")
    return dest


def test_monorepo_subfolder_miss_is_rescued_by_manifest_scan(tmp_path):
    dest = _monorepo(tmp_path)
    # Registry points at docs/; the server lives in packages/server/.
    out = gs.grade_checkout(dest, "docs")
    assert out["outcome"] == "graded", out
    assert out["found_via"] == "manifest-scan"
    assert out["scanned_dirs"] == ["docs", "packages/server"]
    assert out["manifest_dirs"] == ["packages/server"]
    assert [f["file"] for f in out["files"]] == ["packages/server/server.py"]
    assert out["gate"] == 0
    assert out["repo_markers"]["py"] == 1 and out["repo_markers"]["go"] == 0


def test_monorepo_without_manifest_scan_was_a_miss(tmp_path):
    """The old path (grade the subfolder only) finds nothing; this is what the
    49 historical rows could have been."""
    dest = _monorepo(tmp_path)
    assert gs.grade_tree(dest / "docs", base=dest)["outcome"] == "no-handler-found"


RECORDERS = Path(__file__).resolve().parent / "tests" / "fixtures" / "recorders"


def test_grade_tree_passes_package_dir_so_a_sibling_recorder_is_seen():
    """M41: the bench must grade a Python file WITH its directory, the same way
    `service.scan_target` does. `m1_relative_import/` writes its record one
    relative import away: with the directory it is gate 4, and the identical
    source graded bare is gate 0 (the confessed single-file blind spot). Before
    M41 the benchmark reported the gate-0 number for every server of this shape."""
    out = gs.grade_tree(RECORDERS / "m1_relative_import")
    assert out["outcome"] == "graded", out
    assert [f["file"] for f in out["files"]] == ["server.py"]
    assert out["gate"] == 4, out


def test_the_same_fixture_is_gate_0_without_package_dir():
    """The control for the test above: the 4 is caused by `package_dir`, not by
    the fixture being trivially clean."""
    src = (RECORDERS / "m1_relative_import" / "server.py").read_text(encoding="utf-8")
    g = gs.grade_source(src, "server.py")
    assert gs.gate_reached(g, src, "server.py") == 0


def test_classifier_three_reasons_and_unclassified_for_old_rows():
    base = {"outcome": "no-handler-found", "manifest_dirs": [], "scanned_dirs": ["."]}
    go = {**base, "repo_markers": {"go": 3, "rust": 0, "java": 0, "csharp": 0, "py": 0, "ts": 0}}
    assert gs.classify_no_handler(go) == "unsupported-language"
    nothing = {**base, "repo_markers": {"go": 0, "rust": 0, "java": 0, "csharp": 0, "py": 0, "ts": 0}}
    assert gs.classify_no_handler(nothing) == "unsupported-language"   # no .py/.ts at all
    mono = {**base, "repo_markers": {"go": 0, "rust": 0, "java": 0, "csharp": 0, "py": 2, "ts": 0},
            "manifest_dirs": ["examples/demo"], "scanned_dirs": ["."]}
    assert gs.classify_no_handler(mono) == "monorepo-miss"             # examples/ is pruned
    seen = {**mono, "scanned_dirs": [".", "examples/demo"]}
    assert gs.classify_no_handler(seen) == "no-handler"
    old = {"outcome": "no-handler-found", "files": [], "langs": {}}     # a 2026-09-02 row
    assert gs.classify_no_handler(old) == ss.NO_HANDLER_UNCLASSIFIED


def test_historical_49_are_unclassified_and_the_split_sums():
    summ = json.loads(REAL_SUMMARY.read_text(encoding="utf-8"))
    split = summ["no_handler_found_split"]
    assert sum(split.values()) == summ["outcomes"]["no-handler-found"] == 49
    assert split[ss.NO_HANDLER_UNCLASSIFIED] == 49
    assert all(split[r] == 0 for r in ss.NO_HANDLER_REASONS)


def test_covered_respects_prune_between_root_and_manifest():
    assert gs._covered("packages/x", ["."])
    assert not gs._covered("examples/x", ["."])
    assert not gs._covered("packages/x", ["docs"])
    assert gs._covered("packages/x/sub", ["packages/x"])
    assert not gs._covered("packages/x/tests/fixture", ["packages/x"])


# --- M23: summary schema -----------------------------------------------------

def _good_summary():
    return json.loads(REAL_SUMMARY.read_text(encoding="utf-8"))


def test_real_summary_validates_at_schema_1():
    summ = ss.validate_summary(_good_summary())
    assert summ["schema"] == 1
    assert summ["battery_digest"].startswith("unrecorded:")   # the run predates the field


@pytest.mark.parametrize("key", ss.REQUIRED_KEYS)
def test_summary_missing_any_required_key_is_rejected(key):
    summ = _good_summary()
    del summ[key]
    with pytest.raises(ss.SummarySchemaError, match=key):
        ss.validate_summary(summ)


def test_backfill_adds_keys_only_and_never_changes_a_number():
    pre = {k: v for k, v in _good_summary().items()
           if k not in ("schema", "exclusions", "battery_digest", "battery_digest_at_backfill",
                        "checks_run_by_lang", "no_handler_found_split",
                        "no_handler_found_split_note", "backfill_note")}
    rows = [{"files": [{"lang": "py", "checks_run": ["a", "b"]}]},
            {"files": [{"lang": "ts", "checks_run": ["a"]}]}]
    out = ss.backfill(pre, rows, "deadbeef", "2026-09-02T0000Z")
    assert all(out[k] == pre[k] for k in pre)
    assert out["schema"] == 1 and out["checks_run_by_lang"] == {"py": ["a", "b"], "ts": ["a"]}
    assert sum(out["no_handler_found_split"].values()) == pre["outcomes"]["no-handler-found"]


def test_exclusions_are_computed_from_the_summary_numbers():
    ex = ss.exclusions_block(_good_summary())
    by = {e["what"]: e["n"] for e in ex["excluded_from_headline"]}
    assert by["ours"] == 5 and by["no-handler-found"] == 49 and by["clone-failed"] == 18
    assert by["frame-not-sampled"] == 20029 - 100
    assert ex["headline_denominator"]["n"] == 33


# --- M31: Wilson interval ----------------------------------------------------

def test_wilson_interval_on_30_of_33():
    lo, hi = ss.wilson_interval(30, 33)
    assert round(lo, 3) == 0.764 and round(hi, 3) == 0.969
    assert ss.wilson_interval(0, 10)[0] == 0.0
    assert ss.wilson_interval(10, 10)[1] == pytest.approx(1.0)
    with pytest.raises(ValueError):
        ss.wilson_interval(0, 0)


# --- M24-M28 + M32: the renderer --------------------------------------------

def test_report_header_carries_sha_seed_version_and_battery():
    summ = _good_summary()
    text = rr.render(summ)
    header = text.splitlines()[4]
    assert summ["snapshot_sha256"] in header
    assert summ["seed"] in header
    assert summ["mcp_vet_version"] in header
    assert summ["battery_digest"] in header


def test_report_raises_without_exclusions():
    summ = _good_summary()
    del summ["exclusions"]
    with pytest.raises(rr.ReportError, match="exclusions"):
        rr.render(summ)


def test_report_raises_without_own_five_block():
    summ = _good_summary()
    del summ["ours"]
    with pytest.raises(rr.ReportError, match="own-five"):
        rr.render(summ)
    summ["ours"] = []
    with pytest.raises(rr.ReportError, match="own-five"):
        rr.render(summ)


def test_report_opens_with_ours_at_published_gates_outside_denominator():
    text = rr.render(_good_summary())
    ours_at = text.index("## Our own servers first")
    headline_at = text.index("## Headline")
    assert ours_at < headline_at
    block = text[ours_at:headline_at]
    assert "| arcaeon-ledger | graded | 1 (presence)" in block
    for n in ("arcaeon-distill", "arcaeon-once", "arcaeon-continuity", "arcaeon_connector"):
        assert f"| {n} | graded | 0 (no record)" in block
    assert "None of our own servers reaches gate 4" in block
    assert "Not in any denominator" in block
    # The truth rule: nothing implies our servers pass our own checker.
    assert not re.search(r"arcaeon[-_]\w+ \| graded \| 4", text)


def test_report_every_pass_rate_sits_next_to_its_exclusions():
    text = rr.render(_good_summary())
    excl = "Excludes: ours 5; no-handler-found 49; clone-failed 18;"
    for heading in ("## Headline", "## Gate ladder", "## By language"):
        start = text.index(heading)
        end = text.index("\n## ", start + 1)
        assert excl in text[start:end], heading


def test_report_language_rows_carry_checks_run_and_are_not_summed():
    text = rr.render(_good_summary())
    assert "| Python | 8: unsafe-exec" in text
    assert "| TypeScript/JavaScript | 1: audit-record | 22 |" in text
    assert "never averaged" in text
    assert "do not sum to the graded count" in text
    assert "35/" not in text                      # 13 + 22 is never printed as a total


def test_report_headline_has_point_estimate_and_wilson_range():
    text = rr.render(_good_summary())
    assert "**30/33 (90.9%)**" in text
    assert "Wilson" in text and "**76.4% to 96.9%**" in text


def test_blind_spot_paragraph_is_verbatim_from_plan_and_in_the_report():
    plan = re.sub(r"\s+", " ", PLAN.read_text(encoding="utf-8"))
    assert rr.BLIND_SPOT_PARAGRAPH in plan, "PLAN.md paragraph moved; update BLIND_SPOT_PARAGRAPH"
    assert rr.BLIND_SPOT_PARAGRAPH in rr.render(_good_summary())


def test_rendered_report_on_disk_matches_the_summary():
    """The committed report is a pure function of the committed summary."""
    on_disk = (BENCH / "results" / "2026-09-02T2142Z_report.md").read_text(encoding="utf-8")
    assert on_disk == rr.render(_good_summary())


def test_report_never_averages_languages_in_source():
    src = (BENCH / "render_report.py").read_text(encoding="utf-8")
    assert "gate_distribution_graded" in src
    # the per-language dicts are only ever read per lang, never merged
    assert "gate_by_lang'].values()" not in src and 'gate_by_lang"].values()' not in src
