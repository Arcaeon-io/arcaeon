"""Tests for mcp_vet.service.scan_target (R11) — the target-level scan.

The load-bearing property is DETERMINISM (a badge is worthless if a re-run
differs), plus honest scope (missing target raises, non-.py listed as skipped)
and correct server-level aggregation (worst file wins)."""
import json
import pytest

from arcaeon.prove.vet.service import scan_target, TargetGrade

# A plain helper module — no served tool, so nothing to flag. Grades clean.
_CLEAN = "def helper(x):\n    return x.upper()\n"
# A served tool reaching os.system on tool input — unsafe-exec, high.
_BACKDOOR = "from mcp.server.fastmcp import FastMCP\nfrom os import system\nmcp=FastMCP('x')\n@mcp.tool()\ndef run(c):\n    return system(c)\nmcp.run(transport='stdio')\n"


def test_single_file_target(tmp_path):
    f = tmp_path / "server.py"
    f.write_text(_CLEAN, encoding="utf-8")
    g = scan_target(f)
    assert isinstance(g, TargetGrade)
    assert g.files_scanned == ["server.py"]
    assert g.verdict == "no findings in checked classes"


def test_directory_target_worst_file_wins(tmp_path):
    (tmp_path / "clean.py").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "bad.py").write_text(_BACKDOOR, encoding="utf-8")
    g = scan_target(tmp_path)
    assert set(g.files_scanned) == {"bad.py", "clean.py"}
    # server verdict is the WORST file's verdict
    assert g.verdict == "high-severity findings", g.verdict
    assert g.per_file["clean.py"] == "no findings in checked classes"
    assert g.per_file["bad.py"] == "high-severity findings"
    # the backdoor's finding carries its file
    assert any(fd["file"] == "bad.py" and fd["check"] == "unsafe-exec" for fd in g.findings)


def test_deterministic_same_tree_same_digest(tmp_path):
    (tmp_path / "a.py").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "b.py").write_text(_BACKDOOR, encoding="utf-8")
    g1 = scan_target(tmp_path)
    g2 = scan_target(tmp_path)
    assert g1.source_sha256 == g2.source_sha256
    assert g1.to_json() == g2.to_json()   # byte-identical, the whole point


def test_digest_moves_when_a_file_changes(tmp_path):
    (tmp_path / "a.py").write_text(_CLEAN, encoding="utf-8")
    before = scan_target(tmp_path).source_sha256
    (tmp_path / "a.py").write_text(_CLEAN + "\n# edit\n", encoding="utf-8")
    after = scan_target(tmp_path).source_sha256
    assert before != after, "editing a file must move the tree digest"


def test_digest_moves_when_a_file_is_added(tmp_path):
    (tmp_path / "a.py").write_text(_CLEAN, encoding="utf-8")
    before = scan_target(tmp_path).source_sha256
    (tmp_path / "b.py").write_text(_CLEAN, encoding="utf-8")
    after = scan_target(tmp_path).source_sha256
    assert before != after, "adding a file must move the tree digest"


def test_missing_target_raises_not_clean(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_target(tmp_path / "nope")


def test_non_python_files_listed_as_skipped(tmp_path):
    (tmp_path / "server.py").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "README.md").write_text("# hi", encoding="utf-8")
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == ["server.py"]
    assert set(g.files_skipped) == {"README.md", "config.json"}


def test_pycache_pruned(tmp_path):
    (tmp_path / "server.py").write_text(_CLEAN, encoding="utf-8")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "server.cpython-314.pyc").write_text("junk", encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == ["server.py"]
    assert not any("__pycache__" in s for s in g.files_skipped)


def test_pruned_python_files_are_listed_not_vanished(tmp_path):
    """0.0.14 (2026-09-01 audit #4): pruning is by directory NAME. A first-
    party module under a dir named `build/` or `venv/` was neither scanned
    nor listed — the receipt's scope silently excluded it. It is still not
    scanned (the prune stays), but it MUST show in files_skipped."""
    (tmp_path / "server.py").write_text(_CLEAN, encoding="utf-8")
    hidden = tmp_path / "build"
    hidden.mkdir()
    (hidden / "real_handler.py").write_text(_BACKDOOR, encoding="utf-8")
    (hidden / "vendored.so").write_bytes(b"\x00")
    g = scan_target(tmp_path)
    assert g.files_scanned == ["server.py"]
    assert "build/real_handler.py" in g.files_skipped
    assert not any(s.endswith(".so") for s in g.files_skipped)


def test_test_dir_planted_backdoor_is_a_must_miss(tmp_path):
    """Item 146, 2026-09-05: grade-target's own walk did not prune test/fixture
    dirs the way bench/grade_sample.py's harness did, so the self-scan of
    projects/mcp_vet graded its own test/fixture files as production findings
    (FAILURE_DISTRIBUTION_2026-09-02_sample200.md section 1, 33 hits, ALL in
    test_*.py / tests/fixtures/**). A planted `tests/fixture_bad.py` carrying
    a real backdoor pattern must yield ZERO findings — the file is never even
    scanned."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "fixture_bad.py").write_text(_BACKDOOR, encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == []
    assert g.findings == []
    assert "tests/fixture_bad.py" in g.files_skipped


def test_same_content_under_src_is_a_must_hit(tmp_path):
    """The pair to the must-miss above: identical bytes, scanned because they
    sit under `src/` (production code), not `tests/`."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "fixture_bad.py").write_text(_BACKDOOR, encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == ["src/fixture_bad.py"]
    assert g.verdict == "high-severity findings", g.verdict
    assert any(f["check"] == "unsafe-exec" for f in g.findings)


def test_repo_of_only_tests_is_a_third_state_not_a_clean_pass(tmp_path):
    """Item 146's third state: a repo with ONLY test/fixture files must not
    read as "no findings in checked classes" (a clean pass implies something
    was actually looked at and came back clean). It gets its own verdict,
    and it is explicitly excluded from grade.py's _PASS_VERDICTS so nothing
    downstream can mistake it for a check that ran."""
    from arcaeon.prove.vet.grade import _PASS_VERDICTS
    from arcaeon.prove.vet.service import NO_GRADEABLE_FILES
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_thing.py").write_text(_CLEAN, encoding="utf-8")
    (tests_dir / "conftest.py").write_text(_CLEAN, encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == []
    assert g.checks_run == []
    assert g.verdict == NO_GRADEABLE_FILES
    assert g.verdict != "no findings in checked classes"
    assert g.verdict not in _PASS_VERDICTS


def test_conftest_and_test_underscore_files_pruned_at_any_location(tmp_path):
    """Filename-pattern pruning (not just directory-name pruning): mcp_vet's
    OWN test_*.py files live at the package ROOT, not under a tests/
    directory, which is exactly what directory pruning alone would miss."""
    (tmp_path / "server.py").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "test_server.py").write_text(_BACKDOOR, encoding="utf-8")
    (tmp_path / "conftest.py").write_text(_BACKDOOR, encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == ["server.py"]
    assert g.verdict == "no findings in checked classes"
    assert "test_server.py" in g.files_skipped
    assert "conftest.py" in g.files_skipped


def test_fixtures_and_snapshots_dirs_pruned(tmp_path):
    """The two dirs the pre-146 bench harness itself did not prune."""
    (tmp_path / "server.py").write_text(_CLEAN, encoding="utf-8")
    fx = tmp_path / "fixtures"
    fx.mkdir()
    (fx / "bad.py").write_text(_BACKDOOR, encoding="utf-8")
    snap = tmp_path / "__snapshots__"
    snap.mkdir()
    (snap / "bad.py").write_text(_BACKDOOR, encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == ["server.py"]
    assert g.verdict == "no findings in checked classes"


def test_unparseable_file_in_tree_drops_checks_run_and_verdict(tmp_path):
    """0.0.14 (audit critical #1): a tree containing one unparseable file
    cannot claim all checks ran everywhere, and cannot grade pass-class."""
    from arcaeon.prove.vet.grade import _PASS_VERDICTS
    (tmp_path / "server.py").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "broken.py").write_text("def f(:\n  pass\n", encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.checks_run == []
    assert g.verdict not in _PASS_VERDICTS
    assert "0 checks" in g.verdict
