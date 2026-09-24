"""Tests for mcp_vet.badge (R12) — the badge report schema + claim-language gate.

The two load-bearing properties: REQUIRED fields present (a badge that omits
what/when/which-bytes cannot be built), and NO banned verdict language (the
badge never says the server is safe/certified/endorsed)."""
import pytest
from pathlib import Path

from arcaeon.prove.vet.service import scan_target
from arcaeon.prove.vet.badge import (badge_report, assert_no_banned_language,
                           BadgeReport, BadgeClaimError)

_CLEAN = "def helper(x):\n    return x.upper()\n"
_BACKDOOR = "from mcp.server.fastmcp import FastMCP\nfrom os import system\nmcp=FastMCP('x')\n@mcp.tool()\ndef run(c):\n    return system(c)\nmcp.run(transport='stdio')\n"
_TS = "2026-09-01T15:00:00Z"


def _grade(tmp_path, src, name="server.py"):
    (tmp_path / name).write_text(src, encoding="utf-8")
    return scan_target(tmp_path)


def test_badge_has_all_required_fields(tmp_path):
    rep = badge_report(_grade(tmp_path, _CLEAN), scanned_at=_TS)
    assert rep.checks_run.startswith("mcp-vet ")
    assert len(rep.artifact_digest) == 64
    assert rep.scanned_at == _TS
    assert rep.result == "no findings in checked classes"


def test_clean_result_is_the_strongest_claim_and_says_only_itself(tmp_path):
    rep = badge_report(_grade(tmp_path, _CLEAN), scanned_at=_TS)
    # the strongest sayable outcome is the absence of findings — never "safe"
    assert_no_banned_language(rep.result)          # must not raise
    assert "safe" not in rep.result.lower()


def test_backdoor_result_states_findings_in_own_terms(tmp_path):
    rep = badge_report(_grade(tmp_path, _BACKDOOR), scanned_at=_TS)
    assert "high" in rep.result                    # severity counts, its own terms
    assert rep.findings_by_severity.get("high", 0) >= 1


def test_missing_scanned_at_refuses_to_build(tmp_path):
    with pytest.raises(BadgeClaimError):
        badge_report(_grade(tmp_path, _CLEAN), scanned_at="")


def test_pure_transform_same_inputs_same_bytes(tmp_path):
    g = _grade(tmp_path, _BACKDOOR)
    a = badge_report(g, scanned_at=_TS, receipt_id="r1", verify_url="u1")
    b = badge_report(g, scanned_at=_TS, receipt_id="r1", verify_url="u1")
    assert a.to_json() == b.to_json()


def test_receipt_fields_honestly_empty_until_chained(tmp_path):
    rep = badge_report(_grade(tmp_path, _CLEAN), scanned_at=_TS)
    assert rep.receipt_id == "" and rep.verify_url == ""   # stated, not faked


def test_copy_test_catches_banned_words():
    for bad in ("This server is certified safe.",
                "An approved, secure MCP server.",
                "Vetted and trusted by mcp-vet."):
        with pytest.raises(BadgeClaimError):
            assert_no_banned_language(bad)


def test_copy_test_allows_honest_process_language():
    # process descriptions that don't claim safety must pass
    for ok in ("These checks ran on 2026-09-01. 2 high findings.",
                "Checks verified to have run against this artifact.",
                "Scanned; findings listed with line numbers."):
        assert_no_banned_language(ok)   # must not raise


def test_svg_is_deterministic(tmp_path):
    from arcaeon.prove.vet.badge import render_svg
    rep = badge_report(_grade(tmp_path, _BACKDOOR), scanned_at=_TS, receipt_id="r1")
    assert render_svg(rep) == render_svg(rep)


def test_svg_renders_the_governed_fields(tmp_path):
    from arcaeon.prove.vet.badge import render_svg
    rep = badge_report(_grade(tmp_path, _CLEAN), scanned_at=_TS)
    svg = render_svg(rep)
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    assert "mcp-vet scan report" in svg
    assert rep.scanned_at in svg
    assert "sha256:" in svg
    assert "Not a safety certification" in svg   # the honest footer


def test_svg_never_carries_a_banned_word(tmp_path):
    from arcaeon.prove.vet.badge import render_svg, BadgeClaimError
    # a clean badge must NOT render "safe"/"certified" anywhere
    rep = badge_report(_grade(tmp_path, _CLEAN), scanned_at=_TS)
    svg = render_svg(rep).lower()
    # the only allowed occurrence is the footer disclaimer "not a safety certification"
    body = svg.replace("not a safety certification", "")
    for banned in ("certified", " safe", "approved", "endorsed", "guaranteed"):
        assert banned not in body, f"badge image overclaims: {banned!r}"


def test_svg_color_is_status_neutral(tmp_path):
    """clean and findings differ in accent, but NEITHER is green(safe)/red(danger)."""
    from arcaeon.prove.vet.badge import render_svg
    clean = render_svg(badge_report(_grade(tmp_path, _CLEAN), scanned_at=_TS))
    assert "#64748b" in clean            # slate, not green
    (tmp_path / "bad.py").write_text(_BACKDOOR, encoding="utf-8")
    from arcaeon.prove.vet.service import scan_target
    bad = render_svg(badge_report(scan_target(tmp_path), scanned_at=_TS))
    assert "#d97706" in bad               # amber, not red


# --- battery digest (R16b) ----------------------------------------------------

def test_badge_carries_battery_digest_and_it_is_required(tmp_path):
    from arcaeon.prove.vet.badge import battery_digest
    rep = badge_report(_grade(tmp_path, _CLEAN), scanned_at=_TS)
    assert len(rep.battery_digest) == 64
    assert rep.battery_digest == battery_digest()          # recomputable
    # a report stripped of it may not be built
    with pytest.raises(BadgeClaimError, match="battery_digest"):
        from arcaeon.prove.vet.badge import _assert_required
        _assert_required(BadgeReport(checks_run="c", artifact_digest="a", scanned_at=_TS,
                                     result="r", battery_digest="", receipt_id="", verify_url=""))


def test_battery_digest_moves_when_a_check_byte_moves(tmp_path, monkeypatch):
    """The point of the field: same version string, different check body ->
    different digest. Proven by pointing the digest at a copied battery with one
    byte changed, not by editing the real checks.py."""
    import shutil
    import arcaeon.prove.vet.badge as badge
    src = Path(badge.__file__).resolve().parent
    fake = tmp_path / "pkg"
    fake.mkdir()
    for name in badge._BATTERY_MODULES:
        shutil.copy(src / name, fake / name)
    monkeypatch.setattr(badge, "__file__", str(fake / "badge.py"))
    before = badge.battery_digest()
    p = fake / "checks.py"
    p.write_bytes(p.read_bytes() + b"\n# one byte more\n")
    after = badge.battery_digest()
    assert before != after


def test_svg_renders_battery_row(tmp_path):
    from arcaeon.prove.vet.badge import render_svg
    rep = badge_report(_grade(tmp_path, _CLEAN), scanned_at=_TS)
    svg = render_svg(rep)
    assert "battery" in svg and rep.battery_digest[:12] in svg
