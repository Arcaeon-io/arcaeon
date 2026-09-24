"""Tests for `mcp_vet.badge_cli` (batch-100 item 85, 2026-09-05) -- the free
`mcp-vet badge <path>` command: Markdown badge + JSON report, fixture census,
origin note, and the --receipt SIGNED/UNSIGNED contract.

Four scenarios the board asked for, each its own test: a planted clean repo,
a planted high-severity repo, a tests-only repo (NO_GRADEABLE_FILES, grey --
never a pass color), and unsigned vs signed receipts."""
import base64
import json

import pytest

from arcaeon.prove.vet.badge_cli import build_badge, render_badge_text, ORIGIN_NOTE
from arcaeon.prove.vet.service import NO_GRADEABLE_FILES
from arcaeon.prove.vet.badge import assert_no_banned_language, BadgeClaimError

_CLEAN = "def helper(x):\n    return x.upper()\n"
_BACKDOOR = ("from mcp.server.fastmcp import FastMCP\nfrom os import system\n"
             "mcp=FastMCP('x')\n@mcp.tool()\ndef run(c):\n    return system(c)\n"
             "mcp.run(transport='stdio')\n")


def _write(tmp_path, name, src):
    (tmp_path / name).write_text(src, encoding="utf-8")


# --- planted clean repo: green-class pass, never a banned word -------------

def test_clean_repo_is_the_strongest_sayable_pass(tmp_path):
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    j = b["json"]
    assert j["verdict"] == "no findings in checked classes"
    assert j["result"] == "no findings in checked classes"
    assert j["files_scanned"] == ["server.py"]
    assert j["fixture_test_files_pruned"] == 0
    assert_no_banned_language(j["result"])           # never "safe"/"certified"


def test_clean_repo_svg_accent_is_slate_not_green(tmp_path):
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    assert 'stroke="#64748b"' in b["svg"]      # the established "clean" slate, not green


# --- planted high-severity repo: red-class, amber accent -------------------

def test_high_severity_repo_reports_findings_in_its_own_terms(tmp_path):
    _write(tmp_path, "server.py", _BACKDOOR)
    b = build_badge(str(tmp_path))
    j = b["json"]
    assert j["verdict"] == "high-severity findings"
    assert "high" in j["result"]
    assert j["findings_by_severity"].get("high", 0) >= 1
    assert 'stroke="#d97706"' in b["svg"]      # amber, not red


# --- tests-only repo: NO_GRADEABLE_FILES, grey, never a clean pass ---------

def test_tests_only_repo_is_no_gradeable_files_not_a_clean_pass(tmp_path):
    _write(tmp_path, "test_thing.py", "def test_a():\n    assert True\n")
    b = build_badge(str(tmp_path))
    j = b["json"]
    assert j["verdict"] == NO_GRADEABLE_FILES
    assert j["result"] == NO_GRADEABLE_FILES
    assert j["files_scanned"] == []
    assert j["fixture_test_files_pruned"] == 1        # the planted test file, pruned
    # The accent lives on the two rect elements (the border stroke and the
    # left bar); the footer text is ALWAYS #64748b regardless of accent, so
    # checking the accent-bearing tags specifically is the only honest way to
    # tell "this badge's accent is grey" from "this badge's footer exists."
    assert 'stroke="#6b7280"' in b["svg"]
    assert 'fill="#6b7280"' in b["svg"]
    assert 'stroke="#d97706"' not in b["svg"]          # never borrows the findings amber


def test_tests_only_repo_is_never_reported_as_a_pass_verdict(tmp_path):
    """The whole point of the third state: a reader must not be able to read
    'no gradeable files' as 'checked, and clean' by pattern-matching on the
    word 'no'."""
    _write(tmp_path, "test_thing.py", "def test_a():\n    assert True\n")
    b = build_badge(str(tmp_path))
    assert b["json"]["verdict"] != "no findings in checked classes"


def test_fixture_pruned_directory_form_also_counted(tmp_path):
    (tmp_path / "tests").mkdir()
    _write(tmp_path / "tests", "test_thing.py", "def test_a():\n    assert True\n")
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    j = b["json"]
    assert j["fixture_test_files_pruned"] == 1
    assert j["files_scanned"] == ["server.py"]


# --- fixture census + origin note ------------------------------------------

def test_fixture_coverage_is_present_and_nonzero_for_every_check(tmp_path):
    """The census reads mcp_vet's OWN test files (this is a source checkout),
    so every one of its 9 shipped checks should show at least one must-hit AND
    one must-miss -- if a check ever shipped with no clean negative, this is
    where that gap would show."""
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    census = b["json"]["fixture_coverage"]
    assert census["available"] is True
    for check in b["json"]["checks_run"]:
        counts = census["per_check"][check]
        assert counts["must_hit"] >= 1, f"{check} has no must-hit fixture counted"
        # secret-in-code and audit-record route through a shared helper
        # (README/fixture_census.py docstring: a known undercount), so they
        # are not held to the must_miss >= 1 floor here.
        if check not in ("secret-in-code", "audit-record", "except-returns-success"):
            assert counts["must_miss"] >= 1, f"{check} has no must-miss fixture counted"


def test_origin_note_is_verbatim_and_present(tmp_path):
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    assert b["json"]["origin_note"] == ORIGIN_NOTE
    assert "third verdict" in ORIGIN_NOTE
    assert "wrong-layer positive control" in ORIGIN_NOTE
    assert "borrowed-index principle" in ORIGIN_NOTE


def test_not_a_certification_sentence_present_and_clean(tmp_path):
    """Mirrors badge.py's own FOOTER_LINE_2 ('Not a safety certification.'):
    the sentence's whole job is to DISCLAIM the word, so it is exempt from
    `assert_no_banned_language` the same way the footer already is (that
    regex cannot tell affirmation from negation). What it must never do is
    smuggle in an AFFIRMATIVE banned word alongside the disclaimer."""
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    sentence = b["json"]["not_a_certification"]
    assert "not a security certification" in sentence
    lowered = sentence.lower()
    for affirmative in ("safe", "secure", "trusted", "approved", "endorsed",
                        "vetted", "guaranteed"):
        assert affirmative not in lowered, sentence


# --- markdown line -----------------------------------------------------------

def test_markdown_line_is_a_self_contained_data_uri_image(tmp_path):
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    md = b["markdown"]
    assert md.startswith("![mcp-vet scan report](data:image/svg+xml;base64,")
    assert md.endswith(")")
    b64 = md.split("base64,", 1)[1].rsplit(")", 1)[0]
    decoded = base64.b64decode(b64).decode("utf-8")
    assert decoded == b["svg"]


def test_render_badge_text_is_markdown_then_json(tmp_path):
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    text = render_badge_text(b)
    assert text.startswith(b["markdown"])
    tail = text[len(b["markdown"]):].strip()
    parsed = json.loads(tail)
    assert parsed == b["json"]


# --- --receipt: SIGNED / UNSIGNED, never silently ---------------------------

def test_unsigned_by_default(tmp_path):
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path))
    r = b["json"]["receipt"]
    assert r["signed"] is False
    assert r["status"].startswith("UNSIGNED")


def test_receipt_flag_signs_when_a_backend_is_available(tmp_path, receipt_key):
    from arcaeon.prove.vet import receipts
    if not receipts.RECEIPTS_AVAILABLE:
        pytest.skip("no Ed25519 backend installed (arcaeon[sign])")
    _write(tmp_path, "server.py", _CLEAN)
    b = build_badge(str(tmp_path), receipt=True)
    r = b["json"]["receipt"]
    assert r["signed"] is True
    assert r["status"] == "SIGNED"
    assert r["signer_did"].startswith("did:key:z")
    assert r["signer_did"] == r["receipt"]["payload"]["iss"]


def test_receipt_flag_reports_unsigned_never_silently_without_backend(tmp_path, monkeypatch, receipt_key):
    """Simulate the no-backend case directly against `_receipt_block` (the
    real no-backend case depends on which optional deps happen to be
    installed in the test environment, so it is monkeypatched here rather
    than skipped): a caller must get an explicit UNSIGNED status, never a
    silent success and never a bare exception."""
    from arcaeon.prove.vet import badge_cli, receipts

    class _Boom(receipts.ReceiptsUnavailable):
        pass

    def _raise(*a, **k):
        raise _Boom("no Ed25519 backend (simulated)")

    monkeypatch.setattr(receipts, "sign_grade", _raise)
    _write(tmp_path, "server.py", _CLEAN)
    from arcaeon.prove.vet.service import scan_target
    g = scan_target(tmp_path)
    block = badge_cli._receipt_block(g)
    assert block["signed"] is False
    assert block["status"].startswith("UNSIGNED")
    assert "simulated" in block["status"]


def test_receipt_key_source_reports_none_when_nothing_provisioned(tmp_path, monkeypatch):
    from arcaeon.prove.vet import receipts, badge_cli
    monkeypatch.delenv(receipts.RECEIPT_KEY_ENV, raising=False)
    monkeypatch.setattr(receipts, "RECEIPT_KEY_FILE",
                        tmp_path / "does_not_exist.key")
    assert badge_cli._key_source() == "none"


def test_receipt_with_no_key_anywhere_is_unsigned_and_says_so(tmp_path, monkeypatch):
    """qa-fixes item 6: no env var, no key file -> UNSIGNED with the reason,
    never a signature from an ephemeral key nobody holds, and never a read of
    a home-directory default (there is none)."""
    from arcaeon.prove.vet import receipts
    monkeypatch.delenv(receipts.RECEIPT_KEY_ENV, raising=False)
    assert receipts.RECEIPT_KEY_FILE is None
    _write(tmp_path, "server.py", _CLEAN)
    r = build_badge(str(tmp_path), receipt=True)["json"]["receipt"]
    assert r["signed"] is False
    assert r["status"].startswith("UNSIGNED")
    if receipts.RECEIPTS_AVAILABLE:
        assert receipts.RECEIPT_KEY_ENV in r["status"]
    else:
        assert "arcaeon[sign]" in r["status"]


def test_fixture_coverage_root_never_names_a_missing_path(tmp_path):
    """qa-fixes item 8: in a wheel install the census root pointed at a
    nonexistent venv path. With no test files it is None plus a note."""
    from arcaeon.prove.vet import fixture_census
    empty = tmp_path / "no_tests_here"
    c = fixture_census.fixture_coverage(["x"], root=empty)
    assert c["available"] is False
    import unittest.mock as m
    with m.patch.object(fixture_census, "_project_root", return_value=empty):
        c = fixture_census.fixture_coverage(["x"])
    assert c["available"] is False and c["root"] is None and c["note"]
