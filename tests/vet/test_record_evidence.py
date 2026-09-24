"""M35 + M37 (2026-09-02): record_static vs record_dynamic never merge, and the
badge says what the mark is ("receipted, not reviewed").

Two facts, two fields, two rows. The scanner infers a record write from bytes;
a runner observes a record land. A badge built from a static-only grade must
not be able to say or imply the second."""
import dataclasses
import re

import pytest

from arcaeon.prove.vet.badge import (badge_report, render_svg, BadgeClaimError,
                           RECEIPTED_NOT_REVIEWED, FOOTER_LINE_1, FOOTER_LINE_2,
                           _RUNTIME_NOT_CONFIRMED, _RUNTIME_OBSERVED, _RUNTIME_ABSENT)
from arcaeon.prove.vet.grade import grade_source, dynamic_record, Grade
from arcaeon.prove.vet.service import scan_target

_TS = "2026-09-02T16:00:00Z"
_CLEAN = "def helper(x):\n    return x.upper()\n"
_SERVED_NO_RECORD = (
    "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
    "@mcp.tool()\ndef add(a, b):\n    return a + b\n"
    "mcp.run(transport='stdio')\n"
)


# --- M35: the two fields on Grade -------------------------------------------

def test_grade_carries_two_distinct_record_fields():
    g = grade_source(_SERVED_NO_RECORD, "server.py")
    assert isinstance(g.record_static, dict)
    assert g.record_static["evidence"] == "static"
    assert g.record_dynamic is None
    assert g.schema == 2
    # the two are separate keys in the serialized artifact too
    js = g.to_json()
    assert '"record_static"' in js and '"record_dynamic": null' in js


def test_static_field_reports_what_the_scanner_asked():
    served = grade_source(_SERVED_NO_RECORD, "server.py").record_static
    assert served["asked"] is True
    assert served["presence"] is False           # no record write in these bytes
    assert served["gates_met"] == 0
    helper = grade_source(_CLEAN, "helper.py").record_static
    assert helper["asked"] is False              # nothing served, nothing asked
    assert helper["gates"] is None


def test_grade_source_never_fills_record_dynamic():
    for src in (_CLEAN, _SERVED_NO_RECORD):
        assert grade_source(src, "s.py").record_dynamic is None


def test_dynamic_record_is_the_only_shape_and_it_validates():
    d = dynamic_record(True, record_path="C:/x/calls.jsonl", runner="own_five_probe",
                       observed_at=_TS, tool_called="add")
    assert d["evidence"] == "dynamic" and d["observed"] is True
    with pytest.raises(TypeError):
        dynamic_record("yes", record_path="p", runner="r", observed_at=_TS, tool_called="t")
    with pytest.raises(ValueError):
        dynamic_record(True, record_path="", runner="r", observed_at=_TS, tool_called="t")


# --- M35: the badge never merges them ----------------------------------------

def _static_only_grade() -> Grade:
    return grade_source(_SERVED_NO_RECORD, "server.py")


def test_badge_from_static_only_grade_says_runtime_not_confirmed():
    rep = badge_report(_static_only_grade(), scanned_at=_TS)
    assert rep.record_dynamic == _RUNTIME_NOT_CONFIRMED
    assert rep.record_static.startswith("static:")
    # the static line may not borrow runtime vocabulary
    assert not re.search(r"\b(observed|confirmed|runner|launched|executed)\b",
                         rep.record_static, re.IGNORECASE)
    svg = render_svg(rep)
    assert _RUNTIME_NOT_CONFIRMED in svg
    assert _RUNTIME_OBSERVED not in svg


def test_badge_from_target_grade_without_record_fields_stays_honest(tmp_path):
    # service.TargetGrade predates the two fields; the badge must not invent them
    (tmp_path / "server.py").write_text(_SERVED_NO_RECORD, encoding="utf-8")
    rep = badge_report(scan_target(tmp_path), scanned_at=_TS)
    assert rep.record_static == "static: not inferred (grade carries no record_static)"
    assert rep.record_dynamic == _RUNTIME_NOT_CONFIRMED


def test_badge_with_dynamic_record_draws_both_rows_separately():
    g = _static_only_grade()
    g_dyn = dataclasses.replace(
        g, record_dynamic=dynamic_record(True, record_path="C:/x/calls.jsonl",
                                         runner="own_five_probe", observed_at=_TS,
                                         tool_called="add"))
    rep = badge_report(g_dyn, scanned_at=_TS)
    assert rep.record_dynamic == _RUNTIME_OBSERVED
    # static row is unchanged by the runner's observation: still 0/4 from bytes
    assert rep.record_static == badge_report(g, scanned_at=_TS).record_static
    svg = render_svg(rep)
    assert svg.count(">record<") == 2          # two rows, both labelled record
    assert _RUNTIME_OBSERVED in svg and rep.record_static in svg


def test_badge_with_negative_dynamic_record_says_absent_not_confirmed():
    g = dataclasses.replace(
        _static_only_grade(),
        record_dynamic=dynamic_record(False, record_path="p", runner="r",
                                      observed_at=_TS, tool_called="t"))
    assert badge_report(g, scanned_at=_TS).record_dynamic == _RUNTIME_ABSENT


def test_badge_refuses_a_malformed_dynamic_field():
    g = dataclasses.replace(_static_only_grade(), record_dynamic={"evidence": "static"})
    with pytest.raises(BadgeClaimError):
        badge_report(g, scanned_at=_TS)


# --- M37: what the mark is ----------------------------------------------------

def test_footer_leads_with_the_exact_phrase():
    assert RECEIPTED_NOT_REVIEWED == "receipted, not reviewed"
    assert FOOTER_LINE_1.startswith(RECEIPTED_NOT_REVIEWED)
    assert "which checks ran on which bytes" in FOOTER_LINE_1
    assert "No human reviewed this server" in FOOTER_LINE_2


def test_svg_copy_test_receipted_not_reviewed():
    svg = render_svg(badge_report(_static_only_grade(), scanned_at=_TS))
    assert RECEIPTED_NOT_REVIEWED in svg
    assert FOOTER_LINE_1 in svg and FOOTER_LINE_2 in svg
    assert "Not a safety certification" in svg     # the old promise is kept
    assert "reviewed by" not in svg.lower()        # never implies a human review
